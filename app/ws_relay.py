"""
SecureShare — VPS WebSocket relay transfer.

Both sender and receiver connect to the same VPS relay server:
  wss://secureshare-relay.duckdns.org

The server pairs clients by session code and pipes raw bytes.
All data is E2E encrypted — the server never inspects content.

Protocol phases:
  1. Key Exchange + Version Negotiation (signaling-encrypted)
     Both sides send X25519 public key + protocol_version + app_version.
     If versions are incompatible → clear error message → abort.
  2. Verification (signaling-encrypted)
     Both sides confirm verification code matches (user interaction).
  3. File Transfer (E2E encrypted with derived key)
     Sender: metadata → chunks → done
     Receiver: meta_ack → done_ack (with SHA-256 result)

Wire format:
  [1 byte type][payload]

  'S' (0x53)  signaling : signaling_encrypt(JSON)
  'C' (0x43)  control   : e2e_encrypt(JSON)
  'D' (0x44)  data      : [4B seq BE] e2e_encrypt(compressed_chunk)

Control message types (JSON field "type"):
  relay_meta        sender → receiver   file info
  relay_meta_ack    receiver → sender   ready to receive
  relay_done        sender → receiver   all chunks sent
  relay_done_ack    receiver → sender   SHA-256 result
  relay_retransmit  receiver → sender   list of missing chunk indices
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import queue
import struct
import threading
import time
import zlib
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger(__name__)

try:
    import websocket          # websocket-client (sync API)
    _HAS_WS = True
except ImportError:
    _HAS_WS = False

from .config import (
    VPS_RELAY_URL,
    VPS_CHUNK_SIZE,
    APP_VERSION,
    PROTOCOL_VERSION,
    MIN_PROTOCOL_VERSION,
)
from .crypto_utils import (
    CryptoSession,
    derive_signaling_key,
    signaling_encrypt,
    signaling_decrypt,
)

ProgressCB = Callable[[int, int, float], None]
StatusCB   = Callable[[str], None]
VerifyCB   = Callable[[str], bool]   # verification_code → user_confirmed

_SIG = 0x53   # 'S'  signaling frame (key exchange / verification)
_CTL = 0x43   # 'C'  control frame   (E2E encrypted)
_DAT = 0x44   # 'D'  data frame      (E2E encrypted)

_COMPRESS_FLAG = 0x01
_RAW_FLAG      = 0x00


# ── Compression helpers ────────────────────────────────────────────

def _compress(data: bytes) -> bytes:
    c = zlib.compress(data, level=1)
    return (bytes([_COMPRESS_FLAG]) + c) if len(c) < len(data) - 64 else (bytes([_RAW_FLAG]) + data)


def _decompress(data: bytes) -> bytes:
    return zlib.decompress(data[1:]) if data[0] == _COMPRESS_FLAG else data[1:]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


# ── Key Exchange (common for sender and receiver) ─────────────────

def _do_key_exchange(
    ws,
    session_code: str,
    on_status: Optional[StatusCB],
) -> Optional[CryptoSession]:
    """
    Perform X25519 key exchange over the WebSocket with version negotiation.

    Both sides send their public key + protocol version simultaneously
    (signaling-encrypted).  The VPS relay pipes A→B and B→A, so each
    side receives the other's key.

    Version check:
      - If peer's protocol_version < our MIN_PROTOCOL_VERSION → reject
      - If peer's protocol_version is missing → treat as version 0

    Returns CryptoSession with derived shared key, or None on failure.
    """
    crypto = CryptoSession(session_code)
    sig_key = derive_signaling_key(session_code)

    # Send our public key + version info
    pub_key_b64 = base64.b64encode(crypto.get_public_key_bytes()).decode()
    sig_payload = json.dumps({
        "type":             "pub_key",
        "key":              pub_key_b64,
        "protocol_version": PROTOCOL_VERSION,
        "app_version":      APP_VERSION,
    }).encode()
    ws.send_binary(bytes([_SIG]) + signaling_encrypt(sig_key, sig_payload))

    if on_status:
        on_status("🔑 Обмін ключами...")

    # Receive peer's public key (blocks until peer connects + sends)
    try:
        raw = ws.recv()
    except Exception as e:
        if on_status:
            on_status(f"❌ Помилка обміну ключами: {e}")
        return None

    if not raw or not isinstance(raw, bytes) or len(raw) < 2 or raw[0] != _SIG:
        if on_status:
            on_status("❌ Невірний формат обміну ключами")
        return None

    try:
        peer_msg = json.loads(signaling_decrypt(sig_key, raw[1:]))
    except Exception:
        if on_status:
            on_status("❌ Помилка розшифрування ключа партнера")
        return None

    if peer_msg.get("type") != "pub_key" or "key" not in peer_msg:
        if on_status:
            on_status("❌ Невірне повідомлення обміну ключами")
        return None

    # ── Version compatibility check ─────────────────────────────
    peer_proto = peer_msg.get("protocol_version", 0)
    peer_app   = peer_msg.get("app_version", "unknown")

    log.info(
        "Version negotiation: us=proto%d/app%s, peer=proto%d/app%s",
        PROTOCOL_VERSION, APP_VERSION, peer_proto, peer_app,
    )

    if peer_proto < MIN_PROTOCOL_VERSION:
        if on_status:
            on_status(
                f"❌ Несумісна версія партнера (протокол v{peer_proto}, "
                f"потрібно v{MIN_PROTOCOL_VERSION}+). "
                f"Попросіть партнера оновити програму."
            )
        return None

    if PROTOCOL_VERSION < peer_proto:
        # Peer requires a newer protocol — we might be too old
        log.warning(
            "Peer has newer protocol version (%d > %d). "
            "Consider updating the app.",
            peer_proto, PROTOCOL_VERSION,
        )
        if on_status:
            on_status(
                f"⚠️ Партнер має новішу версію (v{peer_app}). "
                f"Рекомендуємо оновити програму."
            )

    # ── Derive shared key ───────────────────────────────────────
    peer_pub_key = base64.b64decode(peer_msg["key"])
    crypto.derive_shared_key(peer_pub_key)

    return crypto


def _do_verification(
    ws,
    crypto: CryptoSession,
    sig_key: bytes,
    on_verify: VerifyCB,
    on_status: Optional[StatusCB],
) -> bool:
    """
    Show verification code and exchange confirmation with peer.

    Returns True if both sides verified successfully.
    """
    verification_code = crypto.get_verification_code()

    if on_status:
        on_status(f"🔑 Код верифікації: {verification_code}")

    # Ask user to verify
    if not on_verify(verification_code):
        # User rejected — notify peer
        reject_payload = json.dumps({"type": "verify_reject"}).encode()
        try:
            ws.send_binary(bytes([_SIG]) + signaling_encrypt(sig_key, reject_payload))
        except Exception:
            pass
        if on_status:
            on_status("❌ Верифікацію відхилено")
        return False

    # Send verification confirmation
    confirm_payload = json.dumps({"type": "verified"}).encode()
    ws.send_binary(bytes([_SIG]) + signaling_encrypt(sig_key, confirm_payload))

    if on_status:
        on_status("✅ Верифікацію підтверджено, чекаю підтвердження від партнера...")

    # Wait for peer's verification
    try:
        raw = ws.recv()
    except Exception as e:
        if on_status:
            on_status(f"❌ Помилка верифікації: {e}")
        return False

    if not raw or not isinstance(raw, bytes) or len(raw) < 2 or raw[0] != _SIG:
        if on_status:
            on_status("❌ Невірний формат верифікації")
        return False

    try:
        peer_msg = json.loads(signaling_decrypt(sig_key, raw[1:]))
    except Exception:
        if on_status:
            on_status("❌ Помилка розшифрування верифікації")
        return False

    if peer_msg.get("type") == "verify_reject":
        if on_status:
            on_status("❌ Партнер відхилив верифікацію")
        return False

    if peer_msg.get("type") != "verified":
        if on_status:
            on_status("❌ Невірне повідомлення верифікації")
        return False

    if on_status:
        on_status("✅ Обидві сторони підтвердили верифікацію")

    return True


# ════════════════════════════════════════════════════════════════════
#  VPSRelaySender
# ════════════════════════════════════════════════════════════════════

class VPSRelaySender:
    """
    Send a file through the VPS relay server.

    Handles the entire flow: connect → key exchange → verify → transfer.
    GUI only needs to provide callbacks for progress, status, and verification.
    """

    def __init__(
        self,
        session_code: str,
        filepath: str | Path,
        on_progress: Optional[ProgressCB] = None,
        on_status:   Optional[StatusCB]   = None,
        on_verify:   Optional[VerifyCB]   = None,
    ):
        self._code       = session_code
        self._filepath   = Path(filepath)
        self.on_progress = on_progress
        self.on_status   = on_status
        self.on_verify   = on_verify or (lambda code: True)
        self._cancelled  = False
        self._ws: Optional[websocket.WebSocket] = None
        self._crypto: Optional[CryptoSession] = None
        self._ctl_queue: queue.Queue = queue.Queue()

    def cancel(self) -> None:
        self._cancelled = True
        try:
            if self._ws:
                self._ws.close()
        except Exception:
            pass

    # ── Public entry point ─────────────────────────────────────────

    def send(self) -> bool:
        """
        Connect to VPS, perform key exchange + verification, send file.
        Returns True on success, False on failure/cancel.
        """
        if not _HAS_WS:
            self._log("❌ Потрібен пакет websocket-client")
            return False
        try:
            return self._send_impl()
        except Exception as exc:
            self._log(f"❌ Помилка: {exc}")
            log.exception("VPSRelaySender error")
            return False
        finally:
            self._close()

    def _send_impl(self) -> bool:
        # ── 1. Connect to VPS ─────────────────────────────────────
        self._log("🌐 Підключаюсь до relay сервера...")
        try:
            self._ws = websocket.WebSocket()
            self._ws.connect(VPS_RELAY_URL, timeout=30)
            self._ws.settimeout(300)       # 5 min to wait for peer
            self._ws.send(self._code)      # register session code
        except Exception as exc:
            self._log(f"❌ Помилка підключення до relay: {exc}")
            return False

        self._log("⏳ Чекаю отримувача...")

        # ── 2. Key exchange ───────────────────────────────────────
        self._crypto = _do_key_exchange(self._ws, self._code, self.on_status)
        if not self._crypto:
            return False

        # ── 3. Verification ───────────────────────────────────────
        sig_key = derive_signaling_key(self._code)
        self._ws.settimeout(120)           # tighten timeout for verification

        if not _do_verification(
            self._ws, self._crypto, sig_key, self.on_verify, self.on_status
        ):
            return False

        # ── 4. Start background receiver ──────────────────────────
        recv_thread = threading.Thread(target=self._recv_worker, daemon=True)
        recv_thread.start()

        # ── 5. Hash file and send metadata ────────────────────────
        file_name = self._filepath.name
        file_size = self._filepath.stat().st_size
        self._log(f"🔍 Обчислюю хеш {file_name}...")
        file_hash    = _sha256_file(self._filepath)
        total_chunks = (file_size + VPS_CHUNK_SIZE - 1) // VPS_CHUNK_SIZE

        self._send_ctl(json.dumps({
            "type":         "relay_meta",
            "name":         file_name,
            "size":         file_size,
            "sha256":       file_hash,
            "chunk_size":   VPS_CHUNK_SIZE,
            "total_chunks": total_chunks,
        }).encode())

        # Wait for meta ACK
        self._log("⏳ Чекаю підтвердження метаданих...")
        try:
            ack = self._ctl_queue.get(timeout=120)
        except queue.Empty:
            self._log("❌ Таймаут метаданих")
            return False
        if ack.get("type") != "relay_meta_ack":
            self._log("❌ Неочікувана відповідь на метадані")
            return False

        # ── 6. Send file chunks ───────────────────────────────────
        size_str = (
            f"{file_size / (1024**3):.1f} ГБ"
            if file_size >= 1024**3
            else f"{file_size / (1024**2):.1f} МБ"
        )
        self._log(f"📦 Надсилаю: {file_name} ({size_str})")

        t0 = time.monotonic()
        sent_bytes = 0
        last_prog  = t0

        with open(self._filepath, "rb") as f:
            for seq in range(total_chunks):
                if self._cancelled:
                    return False

                chunk = f.read(VPS_CHUNK_SIZE)
                if not chunk:
                    break
                self._send_dat(seq, chunk)
                sent_bytes += len(chunk)

                now = time.monotonic()
                if self.on_progress and (now - last_prog >= 0.3):
                    elapsed = now - t0
                    self.on_progress(
                        sent_bytes, file_size,
                        sent_bytes / elapsed if elapsed > 0 else 0,
                    )
                    last_prog = now

        # Final progress
        if self.on_progress:
            elapsed = time.monotonic() - t0
            self.on_progress(
                sent_bytes, file_size,
                sent_bytes / elapsed if elapsed > 0 else 0,
            )

        # ── 7. Send DONE and wait for verification ────────────────
        done_payload = json.dumps({
            "type":         "relay_done",
            "sha256":       file_hash,
            "total_chunks": total_chunks,
        }).encode()
        self._send_ctl(done_payload)
        self._log("⏳ Чекаю підтвердження цілісності...")

        # Retransmit / done-ack loop
        retransmit_rounds = 0
        deadline = time.monotonic() + 600   # 10 min max

        while time.monotonic() < deadline and not self._cancelled:
            try:
                msg = self._ctl_queue.get(timeout=10)
            except queue.Empty:
                # Re-send DONE in case the receiver missed it
                self._send_ctl(done_payload)
                continue

            if msg.get("type") == "relay_done_ack":
                ok = msg.get("verified", False)
                if ok:
                    self._log("🎉 Файл передано та перевірено ✓")
                else:
                    self._log("⚠ Хеш не збігається у отримувача")
                return ok

            elif msg.get("type") == "relay_retransmit" and retransmit_rounds < 5:
                missing = msg.get("missing", [])
                if not missing:
                    continue
                retransmit_rounds += 1
                self._log(
                    f"🔄 Ретрансміт {len(missing)} чанків "
                    f"(раунд {retransmit_rounds})..."
                )
                with open(self._filepath, "rb") as f:
                    for seq_i in missing:
                        if self._cancelled:
                            return False
                        f.seek(seq_i * VPS_CHUNK_SIZE)
                        chunk = f.read(VPS_CHUNK_SIZE)
                        if chunk:
                            self._send_dat(seq_i, chunk)
                self._send_ctl(done_payload)

        self._log("❌ Таймаут очікування підтвердження")
        return False

    # ── Send helpers ───────────────────────────────────────────────

    def _send_ctl(self, plaintext: bytes) -> None:
        try:
            self._ws.send_binary(bytes([_CTL]) + self._crypto.encrypt(plaintext))
        except Exception as exc:
            log.debug("VPS send ctl error: %s", exc)

    def _send_dat(self, seq: int, chunk: bytes) -> None:
        try:
            payload = _compress(chunk)
            payload = self._crypto.encrypt(payload)
            frame   = bytes([_DAT]) + struct.pack("!I", seq) + payload
            self._ws.send_binary(frame)
        except Exception as exc:
            log.debug("VPS send dat error: %s", exc)

    def _recv_worker(self) -> None:
        """Receive control frames from the receiver (runs in background)."""
        try:
            while True:
                raw = self._ws.recv()
                if not raw:
                    break
                if isinstance(raw, bytes) and len(raw) >= 1 and raw[0] == _CTL:
                    try:
                        msg = json.loads(self._crypto.decrypt(raw[1:]))
                        self._ctl_queue.put(msg)
                    except Exception as exc:
                        log.debug("VPS recv ctl decode error: %s", exc)
        except Exception:
            pass

    def _close(self) -> None:
        try:
            if self._ws:
                self._ws.close()
        except Exception:
            pass

    def _log(self, msg: str) -> None:
        log.info("[Sender] %s", msg)
        if self.on_status:
            self.on_status(msg)


# ════════════════════════════════════════════════════════════════════
#  VPSRelayReceiver
# ════════════════════════════════════════════════════════════════════

class VPSRelayReceiver:
    """
    Receive a file through the VPS relay server.

    Handles the entire flow: connect → key exchange → verify → receive.
    GUI only needs to provide callbacks for progress, status, and verification.
    """

    def __init__(
        self,
        session_code: str,
        save_dir: str | Path,
        on_progress: Optional[ProgressCB] = None,
        on_status:   Optional[StatusCB]   = None,
        on_verify:   Optional[VerifyCB]   = None,
    ):
        self._code       = session_code
        self._save_dir   = Path(save_dir)
        self.on_progress = on_progress
        self.on_status   = on_status
        self.on_verify   = on_verify or (lambda code: True)
        self._cancelled  = False
        self._ws: Optional[websocket.WebSocket] = None
        self._crypto: Optional[CryptoSession] = None

    def cancel(self) -> None:
        self._cancelled = True
        try:
            if self._ws:
                self._ws.close()
        except Exception:
            pass

    # ── Public entry point ─────────────────────────────────────────

    def receive(self) -> Optional[Path]:
        """
        Connect to VPS, perform key exchange + verification, receive file.
        Returns Path to saved file on success, None on failure/cancel.
        """
        if not _HAS_WS:
            self._log("❌ Потрібен пакет websocket-client")
            return None
        try:
            return self._receive_impl()
        except Exception as exc:
            self._log(f"❌ Помилка: {exc}")
            log.exception("VPSRelayReceiver error")
            return None
        finally:
            self._close()

    def _receive_impl(self) -> Optional[Path]:
        # ── 1. Connect to VPS ─────────────────────────────────────
        self._log("🌐 Підключаюсь до relay сервера...")
        try:
            self._ws = websocket.WebSocket()
            self._ws.connect(VPS_RELAY_URL, timeout=30)
            self._ws.settimeout(300)       # 5 min to wait for peer
            self._ws.send(self._code)      # register session code
        except Exception as exc:
            self._log(f"❌ Помилка підключення до relay: {exc}")
            return None

        self._log("⏳ Чекаю відправника...")

        # ── 2. Key exchange ───────────────────────────────────────
        self._crypto = _do_key_exchange(self._ws, self._code, self.on_status)
        if not self._crypto:
            return None

        # ── 3. Verification ───────────────────────────────────────
        sig_key = derive_signaling_key(self._code)
        self._ws.settimeout(120)           # tighten timeout for verification

        if not _do_verification(
            self._ws, self._crypto, sig_key, self.on_verify, self.on_status
        ):
            return None

        # ── 4. Receive file ───────────────────────────────────────
        self._log("⏳ Чекаю метадані від відправника...")
        self._ws.settimeout(120)           # transfer timeout

        file_name:     Optional[str]  = None
        file_size:     int            = 0
        file_hash:     str            = ""
        chunk_size:    int            = VPS_CHUNK_SIZE
        total_chunks:  int            = 0
        received_seqs: set[int]       = set()
        bytes_received: int           = 0
        save_path:     Optional[Path] = None
        temp_path:     Optional[Path] = None
        out_file                      = None
        t0 = time.monotonic()
        last_prog = t0

        # Async disk writer (keeps receive loop fast)
        write_queue: queue.Queue = queue.Queue(maxsize=512)
        writer_thread: Optional[threading.Thread] = None

        def _writer() -> None:
            writes = 0
            while True:
                item = write_queue.get()
                if item is None:                      # sentinel
                    if out_file and not out_file.closed:
                        try:
                            out_file.flush()
                        except Exception:
                            pass
                    write_queue.task_done()
                    break
                s, data = item
                try:
                    out_file.seek(s * chunk_size)
                    out_file.write(data)
                    writes += 1
                    if writes % 128 == 0:
                        out_file.flush()
                except Exception:
                    pass
                write_queue.task_done()

        try:
            while not self._cancelled:
                # Receive next frame
                try:
                    raw = self._ws.recv()
                except Exception:
                    break

                if not raw or not isinstance(raw, bytes):
                    continue

                msg_type = raw[0]

                # ── Control frame ──────────────────────────────────
                if msg_type == _CTL:
                    try:
                        msg = json.loads(self._crypto.decrypt(raw[1:]))
                    except Exception:
                        continue

                    t = msg.get("type")

                    if t == "relay_meta":
                        file_name    = msg["name"]
                        file_size    = msg["size"]
                        file_hash    = msg["sha256"]
                        chunk_size   = msg.get("chunk_size", VPS_CHUNK_SIZE)
                        total_chunks = msg.get("total_chunks", 0)

                        save_path = self._save_dir / file_name
                        temp_path = save_path.with_suffix(save_path.suffix + ".part")

                        try:
                            out_file = open(temp_path, "w+b")
                            # Pre-allocate to avoid fragmentation
                            if file_size > 0:
                                out_file.seek(file_size - 1)
                                out_file.write(b"\x00")
                                out_file.flush()
                                out_file.seek(0)
                        except Exception as exc:
                            self._log(f"❌ Не вдалось створити файл: {exc}")
                            return None

                        writer_thread = threading.Thread(
                            target=_writer, daemon=True, name="vps-relay-writer"
                        )
                        writer_thread.start()

                        size_str = (
                            f"{file_size / (1024**3):.1f} ГБ"
                            if file_size >= 1024**3
                            else f"{file_size / (1024**2):.1f} МБ"
                        )
                        self._log(f"📥 Отримую: {file_name} ({size_str})")

                        # Send meta ACK → sender starts streaming
                        self._send_ctl(
                            json.dumps({"type": "relay_meta_ack"}).encode()
                        )
                        t0 = time.monotonic()
                        last_prog = t0

                    elif t == "relay_done":
                        total_chunks = msg.get("total_chunks", total_chunks)
                        file_hash    = msg.get("sha256", file_hash)

                        missing = sorted(set(range(total_chunks)) - received_seqs)

                        if missing:
                            # Request retransmit in batches
                            BATCH = 1000
                            for i in range(0, len(missing), BATCH):
                                batch = missing[i: i + BATCH]
                                self._send_ctl(json.dumps({
                                    "type":    "relay_retransmit",
                                    "missing": batch,
                                }).encode())
                            self._log(
                                f"🔄 Запитую ретрансміт {len(missing)} чанків..."
                            )

                        else:
                            # All chunks present → flush writer → verify
                            write_queue.put(None)
                            write_queue.join()
                            if writer_thread:
                                writer_thread.join(timeout=30)

                            try:
                                out_file.close()
                            except Exception:
                                pass

                            self._log("🔍 Перевірка SHA-256...")
                            verified = _sha256_file(temp_path) == file_hash

                            self._send_ctl(json.dumps({
                                "type":     "relay_done_ack",
                                "verified": verified,
                            }).encode())
                            time.sleep(1)  # let ACK reach sender before closing

                            if verified:
                                if save_path.exists():
                                    save_path.unlink()
                                temp_path.rename(save_path)
                                elapsed = time.monotonic() - t0
                                avg = file_size / elapsed if elapsed > 0 else 0
                                self._log(
                                    f"✅ Збережено: {save_path.name} "
                                    f"({avg / (1024*1024):.1f} МБ/с)"
                                )
                                return save_path
                            else:
                                self._log("❌ Хеш не збігається!")
                                temp_path.unlink(missing_ok=True)
                                return None

                # ── Data frame ─────────────────────────────────────
                elif msg_type == _DAT and file_name:
                    if len(raw) < 5:
                        continue
                    seq      = struct.unpack_from("!I", raw, 1)[0]
                    enc_data = raw[5:]

                    if seq not in received_seqs:
                        try:
                            chunk = _decompress(self._crypto.decrypt(enc_data))
                            received_seqs.add(seq)
                            bytes_received += len(chunk)
                            try:
                                write_queue.put_nowait((seq, chunk))
                            except queue.Full:
                                # Discard; retransmit will cover this slot
                                received_seqs.discard(seq)
                                bytes_received -= len(chunk)
                        except Exception:
                            pass  # corrupted → retransmit will cover it

                    now = time.monotonic()
                    if self.on_progress and file_size and (now - last_prog >= 0.5):
                        elapsed = now - t0
                        self.on_progress(
                            bytes_received, file_size,
                            bytes_received / elapsed if elapsed > 0 else 0,
                        )
                        last_prog = now

        except Exception as exc:
            self._log(f"❌ Помилка: {exc}")
            log.exception("VPSRelayReceiver error")
        finally:
            # Ensure writer thread is stopped
            try:
                write_queue.put(None)
            except Exception:
                pass
            if writer_thread and writer_thread.is_alive():
                writer_thread.join(timeout=10)
            if out_file:
                try:
                    out_file.close()
                except Exception:
                    pass

        # Arrived here on error or cancel
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)
        return None

    # ── Send helper ────────────────────────────────────────────────

    def _send_ctl(self, plaintext: bytes) -> None:
        try:
            self._ws.send_binary(bytes([_CTL]) + self._crypto.encrypt(plaintext))
        except Exception as exc:
            log.debug("VPS recv-side send ctl: %s", exc)

    def _close(self) -> None:
        try:
            if self._ws:
                self._ws.close()
        except Exception:
            pass

    def _log(self, msg: str) -> None:
        log.info("[Receiver] %s", msg)
        if self.on_status:
            self.on_status(msg)
