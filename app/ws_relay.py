"""
SecureShare — WebSocket relay transfer (Cloudflare Tunnel backend).

Sender connects to  ws://localhost:{relay_server.port}
Receiver connects to wss://{cloudflare_url}
The local relay_server.py proxies all frames between them.

No message size limits, no QoS overhead, no broker queues.
All data is E2E encrypted at the application layer; this module
never sees plaintext.

Message framing (binary WebSocket frames):
  [1 B type] [payload]

  type 0x43 ('C')  →  control  : [encrypted JSON]
  type 0x44 ('D')  →  data     : [4 B seq-BE] [encrypted compressed chunk]

Control message types (JSON field "type"):
  relay_meta        sender → receiver   file info
  relay_meta_ack    receiver → sender   ready to receive
  relay_done        sender → receiver   all chunks sent
  relay_done_ack    receiver → sender   SHA-256 result
  relay_retransmit  receiver → sender   list of missing chunk indices
"""

from __future__ import annotations

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

from .config import WS_RELAY_CHUNK_SIZE
from .crypto_utils import CryptoSession

ProgressCB = Callable[[int, int, float], None]
StatusCB   = Callable[[str], None]

_CTL = 0x43   # 'C'  control frame
_DAT = 0x44   # 'D'  data frame

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


# ════════════════════════════════════════════════════════════════════
#  WSRelaySender
# ════════════════════════════════════════════════════════════════════

class WSRelaySender:
    """
    Send a file through the local WebSocket relay server.

    Connects to ws://localhost:{port} (local, direct — not via Cloudflare).

    chunk_start / chunk_stride support parallel multi-tunnel transfers:
      - stride=2, start=0 → sends chunks 0,2,4,6,…  (connection 0)
      - stride=2, start=1 → sends chunks 1,3,5,7,…  (connection 1)
    """

    def __init__(
        self,
        local_ws_url: str,           # ws://localhost:{port}
        session_code: str,
        filepath: str | Path,
        crypto: CryptoSession,
        on_progress: Optional[ProgressCB] = None,
        on_status:   Optional[StatusCB]   = None,
        chunk_start:  int = 0,       # first chunk index owned by this connection
        chunk_stride: int = 1,       # step between owned chunks (1 = all chunks)
    ):
        self._url          = local_ws_url
        self._code         = session_code
        self._filepath     = Path(filepath)
        self._crypto       = crypto
        self.on_progress   = on_progress
        self.on_status     = on_status
        self._cancelled    = False
        self._ws: Optional[websocket.WebSocket] = None
        self._ctl_queue: queue.Queue = queue.Queue()
        self._chunk_start  = chunk_start
        self._chunk_stride = chunk_stride

    def cancel(self) -> None:
        self._cancelled = True
        try:
            if self._ws:
                self._ws.close()
        except Exception:
            pass

    # ── Public entry point ─────────────────────────────────────────

    def send(self) -> bool:
        if not _HAS_WS:
            self._log("❌ WS Relay: потрібен пакет websocket-client")
            return False

        # Connect
        self._log("🌐 WS Relay: підключаюсь до локального relay...")
        try:
            self._ws = websocket.WebSocket()
            self._ws.connect(self._url, timeout=30)
            self._ws.settimeout(120)            # 120s recv timeout during transfer
            self._ws.send(self._code)           # register session code
        except Exception as exc:
            self._log(f"❌ WS Relay: помилка підключення: {exc}")
            return False

        # Start background receiver thread (control messages from peer)
        recv_thread = threading.Thread(target=self._recv_worker, daemon=True)
        recv_thread.start()

        # Keepalive ping to prevent CF Tunnel idle timeout
        self._ping_stop = threading.Event()
        ping_thread = threading.Thread(target=self._ping_worker, daemon=True)
        ping_thread.start()

        # Hash file
        file_name = self._filepath.name
        file_size = self._filepath.stat().st_size
        self._log(f"🌐 WS Relay: обчислюю хеш {file_name}...")
        file_hash    = _sha256_file(self._filepath)
        total_chunks = (file_size + WS_RELAY_CHUNK_SIZE - 1) // WS_RELAY_CHUNK_SIZE

        # Send metadata
        self._send_ctl(json.dumps({
            "type":         "relay_meta",
            "name":         file_name,
            "size":         file_size,
            "sha256":       file_hash,
            "chunk_size":   WS_RELAY_CHUNK_SIZE,
            "total_chunks": total_chunks,
        }).encode())

        # Wait for meta ACK
        self._log("🌐 WS Relay: чекаю підтвердження метаданих...")
        try:
            ack = self._ctl_queue.get(timeout=120)
        except queue.Empty:
            self._log("❌ WS Relay: таймаут метаданих")
            self._close()
            return False
        if ack.get("type") != "relay_meta_ack":
            self._log("❌ WS Relay: неочікувана відповідь на метадані")
            self._close()
            return False

        # My chunks: every chunk_stride-th chunk starting at chunk_start
        my_seqs = list(range(self._chunk_start, total_chunks, self._chunk_stride))

        size_str = (
            f"{file_size / (1024**3):.1f} ГБ"
            if file_size >= 1024**3
            else f"{file_size / (1024**2):.1f} МБ"
        )
        conn_tag = (
            f" [з'єдн. {self._chunk_start+1}/{self._chunk_stride}]"
            if self._chunk_stride > 1 else ""
        )
        self._log(
            f"🌐 WS Relay: передаю {file_name} ({size_str}, "
            f"{len(my_seqs)}/{total_chunks} чанків{conn_tag})"
        )

        t0 = time.monotonic()
        sent_bytes = 0
        last_prog  = t0

        # Window-based flow control using a counter+Condition (race-free).
        # Window = 8 chunks × 512 KB = 4 MB — prevents relay buffer overflow.
        WINDOW_SIZE = 8
        self._window_cond      = threading.Condition()
        self._window_acks_rcvd = 0   # incremented by _recv_worker

        with open(self._filepath, "rb") as f:
            for local_idx, seq in enumerate(my_seqs):
                if self._cancelled:
                    self._close()
                    return False

                # Window boundary based on local (per-connection) index
                if local_idx > 0 and local_idx % WINDOW_SIZE == 0:
                    window_num = local_idx // WINDOW_SIZE
                    with self._window_cond:
                        deadline = time.monotonic() + 120
                        while self._window_acks_rcvd < window_num:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                self._log("❌ WS Relay: таймаут window ACK від отримувача")
                                self._close()
                                return False
                            self._window_cond.wait(timeout=min(remaining, 5))

                f.seek(seq * WS_RELAY_CHUNK_SIZE)
                chunk = f.read(WS_RELAY_CHUNK_SIZE)
                if not chunk:
                    break
                self._send_dat(seq, chunk)
                sent_bytes += len(chunk)
                now = time.monotonic()
                if self.on_progress and (now - last_prog >= 0.3):
                    elapsed = now - t0
                    self.on_progress(sent_bytes, file_size, sent_bytes / elapsed if elapsed > 0 else 0)
                    last_prog = now

        # Final progress snapshot
        if self.on_progress:
            elapsed = time.monotonic() - t0
            self.on_progress(sent_bytes, file_size, sent_bytes / elapsed if elapsed > 0 else 0)

        # Send DONE — include which chunks this connection owns
        done_payload = json.dumps({
            "type":         "relay_done",
            "sha256":       file_hash,
            "total_chunks": total_chunks,
            "chunk_start":  self._chunk_start,
            "chunk_stride": self._chunk_stride,
        }).encode()
        self._send_ctl(done_payload)
        self._log("🌐 WS Relay: чекаю підтвердження / ретрансміт...")

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
                    self._log("🎉 WS Relay: файл передано та перевірено ✓")
                else:
                    self._log("⚠ WS Relay: хеш не збігається у отримувача")
                self._close()
                return ok

            elif msg.get("type") == "relay_retransmit" and retransmit_rounds < 5:
                missing = msg.get("missing", [])
                if not missing:
                    continue
                retransmit_rounds += 1
                self._log(
                    f"🌐 WS Relay: ретрансміт {len(missing)} чанків "
                    f"(раунд {retransmit_rounds})..."
                )
                with open(self._filepath, "rb") as f:
                    for seq in missing:
                        if self._cancelled:
                            self._close()
                            return False
                        f.seek(seq * WS_RELAY_CHUNK_SIZE)
                        chunk = f.read(WS_RELAY_CHUNK_SIZE)
                        if chunk:
                            self._send_dat(seq, chunk)
                self._send_ctl(done_payload)

        self._log("❌ WS Relay: таймаут очікування підтвердження")
        self._close()
        return False

    # ── Send helpers ───────────────────────────────────────────────

    def _send_ctl(self, plaintext: bytes) -> None:
        try:
            self._ws.send_binary(bytes([_CTL]) + self._crypto.encrypt(plaintext))
        except Exception as exc:
            log.debug("WS send ctl error: %s", exc)

    def _send_dat(self, seq: int, chunk: bytes) -> None:
        try:
            payload = _compress(chunk)
            payload = self._crypto.encrypt(payload)
            frame   = bytes([_DAT]) + struct.pack("!I", seq) + payload
            self._ws.send_binary(frame)
        except Exception as exc:
            log.debug("WS send dat error: %s", exc)

    def _ping_worker(self) -> None:
        """Send WebSocket pings every 20s to keep CF Tunnel connection alive."""
        while not self._ping_stop.is_set():
            self._ping_stop.wait(timeout=20)
            if self._ping_stop.is_set():
                break
            try:
                self._ws.ping()
            except Exception:
                break

    def _recv_worker(self) -> None:
        """Receive control frames from the receiver side (runs in background)."""
        try:
            while True:
                raw = self._ws.recv()
                if not raw:
                    break
                if isinstance(raw, bytes) and len(raw) >= 1 and raw[0] == _CTL:
                    try:
                        msg = json.loads(self._crypto.decrypt(raw[1:]))
                        # Window ACK — unblock sender's flow control
                        if msg.get("type") == "relay_window_ack":
                            if hasattr(self, "_window_cond"):
                                with self._window_cond:
                                    self._window_acks_rcvd += 1
                                    self._window_cond.notify_all()
                        else:
                            self._ctl_queue.put(msg)
                    except Exception as exc:
                        log.debug("WS recv ctl decode error: %s", exc)
        except Exception:
            pass

    def _close(self) -> None:
        if hasattr(self, "_ping_stop"):
            self._ping_stop.set()
        try:
            if self._ws:
                self._ws.close()
        except Exception:
            pass

    def _log(self, msg: str) -> None:
        if self.on_status:
            self.on_status(msg)


# ════════════════════════════════════════════════════════════════════
#  WSRelayReceiver
# ════════════════════════════════════════════════════════════════════

class WSRelayReceiver:
    """
    Receive a file through the Cloudflare Tunnel relay.

    Connects to wss://{cloudflare_url}.
    """

    def __init__(
        self,
        relay_url: str,              # wss://xyz.trycloudflare.com
        session_code: str,
        save_dir: str | Path,
        crypto: CryptoSession,
        on_progress: Optional[ProgressCB] = None,
        on_status:   Optional[StatusCB]   = None,
    ):
        # Convert http(s) → ws(s)
        self._url     = relay_url.replace("https://", "wss://").replace("http://", "ws://")
        self._code    = session_code
        self._save_dir = Path(save_dir)
        self._crypto  = crypto
        self.on_progress = on_progress
        self.on_status   = on_status
        self._cancelled  = False
        self._ws: Optional[websocket.WebSocket] = None

    def cancel(self) -> None:
        self._cancelled = True
        try:
            if self._ws:
                self._ws.close()
        except Exception:
            pass

    # ── Public entry point ─────────────────────────────────────────

    def receive(self) -> Optional[Path]:
        if not _HAS_WS:
            self._log("❌ WS Relay: потрібен пакет websocket-client")
            return None

        self._log("🌐 WS Relay: підключаюсь до relay...")
        try:
            self._ws = websocket.WebSocket()
            self._ws.connect(self._url, timeout=30)
            self._ws.settimeout(120)            # 120s recv timeout during transfer
            self._ws.send(self._code)
        except Exception as exc:
            self._log(f"❌ WS Relay: помилка підключення: {exc}")
            return None

        # Keepalive ping to prevent CF Tunnel idle timeout (every 20s)
        _ping_stop = threading.Event()
        def _ping_loop():
            while not _ping_stop.is_set():
                _ping_stop.wait(timeout=20)
                if _ping_stop.is_set():
                    break
                try:
                    self._ws.ping()
                except Exception:
                    break
        threading.Thread(target=_ping_loop, daemon=True).start()

        self._log("🌐 WS Relay: чекаю метадані від відправника...")

        # Transfer state
        file_name:    Optional[str]  = None
        file_size:    int            = 0
        file_hash:    str            = ""
        chunk_size:   int            = WS_RELAY_CHUNK_SIZE
        total_chunks: int            = 0
        received_seqs: set[int]      = set()
        bytes_received: int          = 0
        save_path:    Optional[Path] = None
        temp_path:    Optional[Path] = None
        out_file                     = None
        t0 = time.monotonic()
        last_prog = t0

        # Async disk writer (keeps paho callback fast; same idea as mqtt relay)
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
                        chunk_size   = msg.get("chunk_size", WS_RELAY_CHUNK_SIZE)
                        total_chunks = msg.get("total_chunks", 0)

                        save_path = self._save_dir / file_name
                        temp_path = save_path.with_suffix(save_path.suffix + ".part")

                        try:
                            out_file = open(temp_path, "w+b")
                            # Pre-allocate to avoid fragmentation on large files
                            if file_size > 0:
                                out_file.seek(file_size - 1)
                                out_file.write(b"\x00")
                                out_file.flush()
                                out_file.seek(0)
                        except Exception as exc:
                            self._log(f"❌ WS Relay: не вдалось створити файл: {exc}")
                            return None

                        writer_thread = threading.Thread(
                            target=_writer, daemon=True, name="ws-relay-writer"
                        )
                        writer_thread.start()

                        size_str = (
                            f"{file_size / (1024**3):.1f} ГБ"
                            if file_size >= 1024**3
                            else f"{file_size / (1024**2):.1f} МБ"
                        )
                        self._log(f"🌐 WS Relay: отримую {file_name} ({size_str})")

                        # Send meta ACK → sender starts streaming
                        self._send_ctl(json.dumps({"type": "relay_meta_ack"}).encode())
                        t0 = time.monotonic()
                        last_prog = t0

                    elif t == "relay_done":
                        total_chunks = msg.get("total_chunks", total_chunks)
                        file_hash    = msg.get("sha256", file_hash)

                        missing = sorted(set(range(total_chunks)) - received_seqs)

                        if missing:
                            # Request retransmit in batches of 1000 indices
                            BATCH = 1000
                            for i in range(0, len(missing), BATCH):
                                batch = missing[i: i + BATCH]
                                self._send_ctl(json.dumps({
                                    "type":    "relay_retransmit",
                                    "missing": batch,
                                }).encode())
                            self._log(
                                f"🌐 WS Relay: запитую ретрансміт {len(missing)} чанків..."
                            )
                            # Continue receiving — sender will retransmit then re-send DONE

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

                            self._log("🌐 WS Relay: перевірка SHA-256...")
                            verified = _sha256_file(temp_path) == file_hash

                            self._send_ctl(json.dumps({
                                "type":     "relay_done_ack",
                                "verified": verified,
                            }).encode())
                            time.sleep(1)   # let ACK reach sender before closing

                            if verified:
                                if save_path.exists():
                                    save_path.unlink()
                                temp_path.rename(save_path)
                                elapsed = time.monotonic() - t0
                                avg = file_size / elapsed if elapsed > 0 else 0
                                self._log(
                                    f"Збережено: {save_path} ✓  "
                                    f"({avg / (1024*1024):.1f} МБ/с середня)"
                                )
                                return save_path
                            else:
                                self._log("❌ WS Relay: хеш не збігається!")
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
                            # Flow control: ACK every 128 chunks so sender
                            # doesn't flood the relay buffer
                            if len(received_seqs) % 128 == 0:
                                self._send_ctl(
                                    json.dumps({"type": "relay_window_ack"}).encode()
                                )
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
            self._log(f"❌ WS Relay: {exc}")
            log.exception("WSRelayReceiver error")
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
            try:
                self._ws.close()
            except Exception:
                pass

        # Arrived here on error or cancel
        _ping_stop.set()
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)
        return None

    # ── Send helper ────────────────────────────────────────────────

    def _send_ctl(self, plaintext: bytes) -> None:
        try:
            self._ws.send_binary(bytes([_CTL]) + self._crypto.encrypt(plaintext))
        except Exception as exc:
            log.debug("WS recv-side send ctl: %s", exc)

    def _log(self, msg: str) -> None:
        if self.on_status:
            self.on_status(msg)
