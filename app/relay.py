"""
SecureShare — MQTT relay transfer (fallback).

When direct TCP/UDP connections fail, data is relayed through
the free public MQTT broker.  All data is E2E encrypted so the
broker sees only ciphertext.

v5 design:
  - 64 KB chunks    → safely under public broker message-size limit (~256 KB)
  - QoS 1 for data  → broker guarantees delivery; no app-level retransmit needed
  - QoS 1 for ctl   → meta / done / ack are reliable
  - 16 inflight     → 1 MB max in-flight; won't overflow broker session queue
  - async writer    → paho callback never blocks on disk I/O
  - TLS + hashed topics (security)
"""

from __future__ import annotations

import hashlib
import json
import logging
import queue
import struct
import threading
import time
import uuid
import zlib
from pathlib import Path
from typing import Callable, Optional

import paho.mqtt.client as mqtt

from .config import (
    MQTT_BROKERS,
    MQTT_BROKER,
    MQTT_PORT,
    MQTT_KEEPALIVE,
    MQTT_TOPIC_PREFIX,
    MQTT_RELAY_CHUNK_SIZE,
    MQTT_RELAY_QOS,
    MQTT_RELAY_DATA_QOS,
    MQTT_RELAY_INFLIGHT,
    mqtt_setup_tls,
)
from .crypto_utils import CryptoSession, derive_topic_id

log = logging.getLogger(__name__)

ProgressCB = Callable[[int, int, float], None]
StatusCB   = Callable[[str], None]

_COMPRESS_FLAG = 0x01
_RAW_FLAG      = 0x00


def _compress(data: bytes) -> bytes:
    compressed = zlib.compress(data, level=1)
    if len(compressed) < len(data) - 64:
        return bytes([_COMPRESS_FLAG]) + compressed
    return bytes([_RAW_FLAG]) + data


def _decompress(data: bytes) -> bytes:
    flag    = data[0]
    payload = data[1:]
    return zlib.decompress(payload) if flag == _COMPRESS_FLAG else payload


def _sha256_file(path: str | Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


# ════════════════════════════════════════════════════════════════════
#  MQTT Relay Sender
# ════════════════════════════════════════════════════════════════════

class MQTTRelaySender:
    """
    Send a file through MQTT broker as relay.

    v4: QoS 0 data + token-bucket rate limiter + adaptive back-off.
    """

    def __init__(
        self,
        session_code: str,
        filepath: str | Path,
        crypto: CryptoSession,
        on_progress: Optional[ProgressCB] = None,
        on_status:   Optional[StatusCB]   = None,
    ):
        self.session_code = session_code
        self.filepath     = Path(filepath)
        self.crypto       = crypto
        self.on_progress  = on_progress
        self.on_status    = on_status
        self._cancelled   = False

        topic_id          = derive_topic_id(session_code)
        self._topic_data  = f"{MQTT_TOPIC_PREFIX}/{topic_id}/relay/data"
        self._topic_ctl   = f"{MQTT_TOPIC_PREFIX}/{topic_id}/relay/ctl"

        self._client: Optional[mqtt.Client] = None
        self._connected       = threading.Event()
        self._meta_ack        = threading.Event()
        self._done_ack        = threading.Event()
        self._done_verified   = False

        self._missing_chunks: list[int] = []
        self._missing_lock              = threading.Lock()
        self._retransmit_event          = threading.Event()

    def cancel(self):
        self._cancelled = True

    # ── Public entry point ─────────────────────────────────────────

    def send(self) -> bool:
        file_size    = self.filepath.stat().st_size
        file_name    = self.filepath.name
        file_hash    = self._hash_file(file_name)
        total_chunks = (file_size + MQTT_RELAY_CHUNK_SIZE - 1) // MQTT_RELAY_CHUNK_SIZE

        if not self._connect():
            return False

        # ── Metadata ───────────────────────────────────────────────
        meta = json.dumps({
            "type":         "relay_meta",
            "name":         file_name,
            "size":         file_size,
            "sha256":       file_hash,
            "chunk_size":   MQTT_RELAY_CHUNK_SIZE,
            "total_chunks": total_chunks,
        }).encode()
        self._client.publish(self._topic_ctl, self.crypto.encrypt(meta), qos=MQTT_RELAY_QOS)

        if self.on_status:
            self.on_status("📡 Relay: чекаю підтвердження метаданих...")
        if not self._meta_ack.wait(timeout=120):
            if self.on_status:
                self.on_status("❌ Relay: отримувач не відповів")
            self._cleanup()
            return False

        # ── Stream ────────────────────────────────────────────────
        size_str = (
            f"{file_size/(1024**3):.1f} ГБ"
            if file_size >= 1024**3
            else f"{file_size/(1024**2):.1f} МБ"
        )
        if self.on_status:
            self.on_status(
                f"📡 Relay: передаю {file_name} ({size_str}, {total_chunks} чанків)"
            )

        t0           = time.monotonic()
        sent_bytes   = 0
        last_prog    = t0

        with open(self.filepath, "rb") as f:
            for seq in range(total_chunks):
                if self._cancelled:
                    self._cleanup()
                    return False

                chunk = f.read(MQTT_RELAY_CHUNK_SIZE)
                if not chunk:
                    break

                # QoS 1: paho blocks when inflight window is full (natural rate control)
                self._send_chunk(seq, chunk)
                sent_bytes += len(chunk)

                now = time.monotonic()
                if self.on_progress and (now - last_prog >= 0.3):
                    elapsed = now - t0
                    speed   = sent_bytes / elapsed if elapsed > 0 else 0
                    self.on_progress(sent_bytes, file_size, speed)
                    last_prog = now

        # Final progress snapshot
        if self.on_progress:
            elapsed = time.monotonic() - t0
            speed   = sent_bytes / elapsed if elapsed > 0 else 0
            self.on_progress(sent_bytes, file_size, speed)

        # ── DONE + retransmit loop ─────────────────────────────────
        done_payload = json.dumps({
            "type":         "relay_done",
            "sha256":       file_hash,
            "total_chunks": total_chunks,
        }).encode()

        self._publish_ctl(done_payload)
        if self.on_status:
            self.on_status("📡 Relay: чекаю підтвердження / ретрансміт...")

        retransmit_rounds = 0
        deadline          = time.monotonic() + 300   # 5 min max

        while time.monotonic() < deadline:
            if self._cancelled:
                self._cleanup()
                return False
            if self._done_ack.is_set():
                break

            if self._retransmit_event.wait(timeout=2):
                self._retransmit_event.clear()
                with self._missing_lock:
                    missing = list(self._missing_chunks)
                    self._missing_chunks.clear()

                if missing and retransmit_rounds < 5:
                    retransmit_rounds += 1
                    if self.on_status:
                        self.on_status(
                            f"📡 Relay: ретрансміт {len(missing)} чанків "
                            f"(раунд {retransmit_rounds})..."
                        )
                    # Accumulate all batches before retransmitting
                    # (multiple batches may arrive for the same round)
                    with self._missing_lock:
                        all_missing = sorted(set(missing))
                    with open(self.filepath, "rb") as f:
                        for seq in all_missing:
                            if self._cancelled:
                                break
                            f.seek(seq * MQTT_RELAY_CHUNK_SIZE)
                            chunk = f.read(MQTT_RELAY_CHUNK_SIZE)
                            if chunk:
                                self._send_chunk(seq, chunk)  # QoS 1 guaranteed
                    self._publish_ctl(done_payload)

        ok = self._done_ack.is_set() and self._done_verified
        if self.on_status:
            if ok:
                self.on_status("Файл передано та перевірено через relay! ✓")
            elif self._done_ack.is_set():
                self.on_status("⚠ Relay: помилка верифікації на стороні отримувача")
            else:
                self.on_status("❌ Relay: таймаут")
        self._cleanup()
        return ok

    # ── Helpers ────────────────────────────────────────────────────

    def _hash_file(self, name: str) -> str:
        if self.on_status:
            self.on_status(f"📡 Relay: обчислюю хеш {name}...")
        return _sha256_file(self.filepath)

    def _send_chunk(self, seq: int, chunk: bytes):
        """Compress → encrypt → publish with QoS 1 (broker must deliver)."""
        compressed = _compress(chunk)
        encrypted  = self.crypto.encrypt(compressed)
        payload    = struct.pack("!I", seq) + encrypted
        self._client.publish(self._topic_data, payload, qos=MQTT_RELAY_DATA_QOS)

    def _publish_ctl(self, msg: bytes):
        self._client.publish(
            self._topic_ctl, self.crypto.encrypt(msg), qos=MQTT_RELAY_QOS
        )

    def _connect(self) -> bool:
        client_id    = f"ss-rs-{uuid.uuid4().hex[:8]}"
        self._client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
        )
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._client.max_inflight_messages_set(MQTT_RELAY_INFLIGHT)
        self._client.max_queued_messages_set(0)

        if self.on_status:
            self.on_status("📡 Relay: підключаюсь (TLS)...")
        for broker in MQTT_BROKERS:
            try:
                self._connected.clear()
                mqtt_setup_tls(self._client)
                self._client.connect(broker, MQTT_PORT, keepalive=MQTT_KEEPALIVE)
                self._client.loop_start()
                if self._connected.wait(timeout=15):
                    return True
                self._client.loop_stop()
            except Exception as exc:
                log.warning("Relay MQTT broker %s failed: %s", broker, exc)
                try:
                    self._client.loop_stop()
                except Exception:
                    pass
        if self.on_status:
            self.on_status("❌ Relay: всі брокери недоступні")
        return False

    def _cleanup(self):
        try:
            self._client.loop_stop()
            self._client.disconnect()
        except Exception:
            pass

    # ── MQTT callbacks ─────────────────────────────────────────────

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            client.subscribe(self._topic_ctl, qos=MQTT_RELAY_QOS)
            self._connected.set()

    def _on_message(self, client, userdata, msg):
        if msg.topic != self._topic_ctl:
            return
        try:
            data     = json.loads(self.crypto.decrypt(msg.payload))
            msg_type = data.get("type")
            if msg_type == "relay_meta_ack":
                self._meta_ack.set()
            elif msg_type == "relay_done_ack":
                self._done_verified = data.get("verified", False)
                self._done_ack.set()
            elif msg_type == "relay_retransmit":
                with self._missing_lock:
                    self._missing_chunks = data.get("missing", [])
                self._retransmit_event.set()
        except Exception as exc:
            log.debug("Relay sender ctl: %s", exc)


# ════════════════════════════════════════════════════════════════════
#  MQTT Relay Receiver
# ════════════════════════════════════════════════════════════════════

class MQTTRelayReceiver:
    """
    Receive a file through MQTT broker as relay.
    v4: QoS 0 data + streaming to disk + retransmit requests.
    """

    def __init__(
        self,
        session_code: str,
        save_dir:     str | Path,
        crypto:       CryptoSession,
        on_progress:  Optional[ProgressCB] = None,
        on_status:    Optional[StatusCB]   = None,
    ):
        self.session_code = session_code
        self.save_dir     = Path(save_dir)
        self.crypto       = crypto
        self.on_progress  = on_progress
        self.on_status    = on_status
        self._cancelled   = False

        topic_id         = derive_topic_id(session_code)
        self._topic_data = f"{MQTT_TOPIC_PREFIX}/{topic_id}/relay/data"
        self._topic_ctl  = f"{MQTT_TOPIC_PREFIX}/{topic_id}/relay/ctl"

        self._client: Optional[mqtt.Client] = None
        self._connected      = threading.Event()
        self._meta_received  = threading.Event()
        self._done_received  = threading.Event()

        self._file_name:    Optional[str] = None
        self._file_size:    int           = 0
        self._file_hash:    str           = ""
        self._chunk_size:   int           = MQTT_RELAY_CHUNK_SIZE
        self._total_chunks: int           = 0

        self._received_seqs:  set[int]   = set()
        self._received_lock               = threading.Lock()
        self._bytes_received: int         = 0
        self._temp_file                   = None
        self._t0:             float       = 0.0
        self._last_progress:  float       = 0.0

        # Async disk writer: paho callback just enqueues, writer thread does I/O
        self._write_queue: queue.Queue    = queue.Queue(maxsize=512)
        self._writer_thread: Optional[threading.Thread] = None

    def cancel(self):
        self._cancelled = True

    def receive(self) -> Optional[Path]:
        # ── Connect ────────────────────────────────────────────────
        client_id    = f"ss-rr-{uuid.uuid4().hex[:8]}"
        self._client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
        )
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._client.max_inflight_messages_set(MQTT_RELAY_INFLIGHT)

        if self.on_status:
            self.on_status("📡 Relay: підключаюсь (TLS)...")
        connected = False
        for broker in MQTT_BROKERS:
            try:
                self._connected.clear()
                mqtt_setup_tls(self._client)
                self._client.connect(broker, MQTT_PORT, keepalive=MQTT_KEEPALIVE)
                self._client.loop_start()
                if self._connected.wait(timeout=15):
                    connected = True
                    break
                self._client.loop_stop()
            except Exception as exc:
                log.warning("Relay MQTT broker %s failed: %s", broker, exc)
                try:
                    self._client.loop_stop()
                except Exception:
                    pass
        if not connected:
            if self.on_status:
                self.on_status("❌ Relay: всі брокери недоступні")
            return None

        # ── Wait for metadata ──────────────────────────────────────
        if self.on_status:
            self.on_status("📡 Relay: чекаю метадані...")
        if not self._meta_received.wait(timeout=300):
            if self.on_status:
                self.on_status("❌ Relay: таймаут метаданих")
            self._cleanup()
            return None

        save_path = self.save_dir / self._file_name
        temp_path = save_path.with_suffix(save_path.suffix + ".part")

        try:
            self._temp_file = open(temp_path, "w+b")
            # Pre-allocate file to avoid fragmentation on large files
            if self._file_size > 0:
                self._temp_file.seek(self._file_size - 1)
                self._temp_file.write(b"\x00")
                self._temp_file.flush()
                self._temp_file.seek(0)
        except Exception as exc:
            if self.on_status:
                self.on_status(f"❌ Relay: не вдалось створити файл: {exc}")
            self._cleanup()
            return None

        # Start async writer thread BEFORE receiving data
        self._writer_thread = threading.Thread(
            target=self._writer_worker, daemon=True, name="relay-writer"
        )
        self._writer_thread.start()

        size = self._file_size
        size_str = f"{size/(1024**3):.1f} ГБ" if size >= 1024**3 else f"{size/(1024**2):.1f} МБ"
        if self.on_status:
            self.on_status(f"📡 Relay: отримую {self._file_name} ({size_str})")

        # Send meta ACK
        ack = json.dumps({"type": "relay_meta_ack"}).encode()
        self._client.publish(
            self._topic_ctl, self.crypto.encrypt(ack), qos=MQTT_RELAY_QOS
        )

        self._t0            = time.monotonic()
        self._last_progress = self._t0

        # ── Wait for all data + DONE ───────────────────────────────
        while not self._done_received.is_set():
            if self._cancelled:
                if self._writer_thread and self._writer_thread.is_alive():
                    self._write_queue.put(None)
                    self._writer_thread.join(timeout=5)
                self._close_temp()
                self._cleanup()
                return None
            self._done_received.wait(timeout=1)
            now = time.monotonic()
            if self.on_progress and (now - self._last_progress >= 0.5):
                elapsed = now - self._t0
                speed   = self._bytes_received / elapsed if elapsed > 0 else 0
                self.on_progress(self._bytes_received, self._file_size, speed)
                self._last_progress = now

        # ── Retransmit rounds (safety net — QoS 1 rarely needs this) ─
        for rnd in range(5):
            with self._received_lock:
                received = set(self._received_seqs)
            missing = sorted(set(range(self._total_chunks)) - received)
            if not missing:
                break

            if self.on_status:
                self.on_status(
                    f"📡 Relay: запитую ретрансміт {len(missing)} чанків (раунд {rnd+1})..."
                )
            # Send retransmit requests in batches of 1000 indices each
            # (MQTT message size limit applies to control messages too)
            BATCH = 1000
            for i in range(0, len(missing), BATCH):
                batch = missing[i : i + BATCH]
                req = json.dumps({
                    "type":    "relay_retransmit",
                    "missing": batch,
                }).encode()
                self._client.publish(
                    self._topic_ctl, self.crypto.encrypt(req), qos=MQTT_RELAY_QOS
                )
            self._done_received.clear()
            self._done_received.wait(timeout=60)

        # Final progress
        if self.on_progress:
            elapsed = time.monotonic() - self._t0
            speed   = self._bytes_received / elapsed if elapsed > 0 else 0
            self.on_progress(self._bytes_received, self._file_size, speed)

        # Stop writer thread and wait for all disk I/O to finish
        if self._writer_thread and self._writer_thread.is_alive():
            if self.on_status:
                self.on_status("📡 Relay: очікую запис на диск...")
            self._write_queue.put(None)          # sentinel
            self._writer_thread.join(timeout=60)

        self._close_temp()

        # ── Check completeness ─────────────────────────────────────
        with self._received_lock:
            missing = set(range(self._total_chunks)) - self._received_seqs
        if missing:
            if self.on_status:
                self.on_status(f"❌ Relay: відсутні {len(missing)} чанків після ретрансміту")
            self._send_done_ack(False)
            temp_path.unlink(missing_ok=True)
            self._cleanup()
            return None

        # ── Verify SHA-256 ─────────────────────────────────────────
        if self.on_status:
            self.on_status("📡 Relay: перевірка SHA-256...")
        verified = _sha256_file(temp_path) == self._file_hash
        self._send_done_ack(verified)

        if verified:
            if save_path.exists():
                save_path.unlink()
            temp_path.rename(save_path)
            if self.on_status:
                elapsed   = time.monotonic() - self._t0
                avg_speed = self._file_size / elapsed if elapsed > 0 else 0
                self.on_status(
                    f"Збережено: {save_path} ✓  "
                    f"({avg_speed/(1024*1024):.1f} МБ/с середня)"
                )
            self._cleanup()
            return save_path
        else:
            if self.on_status:
                self.on_status("❌ Relay: хеш не збігається!")
            temp_path.unlink(missing_ok=True)
            self._cleanup()
            return None

    # ── MQTT callbacks ─────────────────────────────────────────────

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            client.subscribe(self._topic_data, qos=MQTT_RELAY_DATA_QOS)
            client.subscribe(self._topic_ctl,  qos=MQTT_RELAY_QOS)
            self._connected.set()

    def _on_message(self, client, userdata, msg):
        try:
            if msg.topic == self._topic_data:
                self._handle_data(msg.payload)
            elif msg.topic == self._topic_ctl:
                self._handle_ctl(msg.payload)
        except Exception as exc:
            log.debug("Relay receiver: %s", exc)

    def _writer_worker(self):
        """Dedicated disk-writer thread.
        Drains _write_queue so paho's on_message callback is never blocked by I/O.
        Writes every 64 chunks (≈48 MB) then flushes once.
        """
        writes_since_flush = 0
        while True:
            item = self._write_queue.get()
            if item is None:          # sentinel — stop
                if self._temp_file and not self._temp_file.closed:
                    try:
                        self._temp_file.flush()
                    except Exception:
                        pass
                self._write_queue.task_done()
                break
            seq, chunk = item
            if self._temp_file and not self._temp_file.closed:
                try:
                    self._temp_file.seek(seq * self._chunk_size)
                    self._temp_file.write(chunk)
                    writes_since_flush += 1
                    if writes_since_flush >= 64:
                        self._temp_file.flush()
                        writes_since_flush = 0
                except Exception:
                    pass
            self._write_queue.task_done()

    def _handle_data(self, payload: bytes):
        """paho callback — must return FAST (no blocking I/O)."""
        seq      = struct.unpack_from("!I", payload, 0)[0]
        enc_data = payload[4:]
        try:
            chunk = _decompress(self.crypto.decrypt(enc_data))
        except Exception:
            return  # corrupted → retransmit will cover it

        with self._received_lock:
            if seq in self._received_seqs:
                return
            self._received_seqs.add(seq)
            self._bytes_received += len(chunk)

        # Non-blocking enqueue; if full, un-register so retransmit re-sends it
        try:
            self._write_queue.put_nowait((seq, chunk))
        except queue.Full:
            with self._received_lock:
                self._received_seqs.discard(seq)
                self._bytes_received -= len(chunk)

    def _handle_ctl(self, payload: bytes):
        try:
            data     = json.loads(self.crypto.decrypt(payload))
            msg_type = data.get("type")
            if msg_type == "relay_meta":
                self._file_name    = data["name"]
                self._file_size    = data["size"]
                self._file_hash    = data["sha256"]
                self._chunk_size   = data.get("chunk_size", MQTT_RELAY_CHUNK_SIZE)
                self._total_chunks = data.get("total_chunks", 0)
                self._meta_received.set()
            elif msg_type == "relay_done":
                self._total_chunks = data.get("total_chunks", self._total_chunks)
                self._file_hash    = data.get("sha256", self._file_hash)
                self._done_received.set()
        except Exception as exc:
            log.debug("Relay receiver ctl: %s", exc)

    def _send_done_ack(self, verified: bool):
        try:
            ack = json.dumps({"type": "relay_done_ack", "verified": verified}).encode()
            self._client.publish(
                self._topic_ctl, self.crypto.encrypt(ack), qos=MQTT_RELAY_QOS
            )
            time.sleep(1)
        except Exception:
            pass

    def _close_temp(self):
        if self._temp_file and not self._temp_file.closed:
            try:
                self._temp_file.close()
            except Exception:
                pass

    def _cleanup(self):
        self._close_temp()
        try:
            self._client.loop_stop()
            self._client.disconnect()
        except Exception:
            pass
