"""
SecureShare — file transfer protocols (TCP & reliable-UDP).

Both protocols:
  1. Exchange encrypted file metadata (name, size, sha256).
  2. Stream encrypted chunks with progress callbacks.
  3. Verify integrity via SHA-256 at the end.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import struct
import socket
import time
import threading
from pathlib import Path
from typing import Callable, Optional

from .config import TCP_CHUNK_SIZE, UDP_PAYLOAD_SIZE, UDP_WINDOW_SIZE
from .crypto_utils import CryptoSession

log = logging.getLogger(__name__)

# Callback signature: (bytes_done, total_bytes, speed_bytes_per_sec)
ProgressCB = Callable[[int, int, float], None]
StatusCB = Callable[[str], None]


# ════════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════════

def _sha256_file(path: str | Path, chunk: int = 1024 * 1024) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from a TCP socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading")
        buf.extend(chunk)
    return bytes(buf)


def _send_msg(sock: socket.socket, crypto: CryptoSession, data: bytes) -> None:
    """Send a length-prefixed encrypted message over TCP."""
    encrypted = crypto.encrypt(data)
    header = struct.pack("!I", len(encrypted))
    sock.sendall(header + encrypted)


def _recv_msg(sock: socket.socket, crypto: CryptoSession) -> bytes:
    """Receive and decrypt a length-prefixed message from TCP."""
    header = _recv_exact(sock, 4)
    length = struct.unpack("!I", header)[0]
    encrypted = _recv_exact(sock, length)
    return crypto.decrypt(encrypted)


# ════════════════════════════════════════════════════════════════════
#  TCP file transfer
# ════════════════════════════════════════════════════════════════════

class TCPSender:
    """Send a file over an established TCP connection."""

    def __init__(
        self,
        sock: socket.socket,
        filepath: str | Path,
        crypto: CryptoSession,
        on_progress: Optional[ProgressCB] = None,
        on_status: Optional[StatusCB] = None,
    ):
        self.sock = sock
        self.filepath = Path(filepath)
        self.crypto = crypto
        self.on_progress = on_progress
        self.on_status = on_status
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def send(self) -> bool:
        """Send the file. Returns True on success."""
        file_size = self.filepath.stat().st_size
        file_name = self.filepath.name

        if self.on_status:
            self.on_status(f"Обчислюю хеш {file_name}...")
        file_hash = _sha256_file(self.filepath)

        # ── Send metadata ──────────────────────────────────────────
        meta = json.dumps({
            "type": "meta",
            "name": file_name,
            "size": file_size,
            "sha256": file_hash,
        }).encode()
        _send_msg(self.sock, self.crypto, meta)

        if self.on_status:
            self.on_status("Метадані відправлено. Чекаю підтвердження...")

        # ── Wait for meta ACK (may contain resume offset) ──────────
        ack_raw = _recv_msg(self.sock, self.crypto)
        ack = json.loads(ack_raw)
        resume_from = ack.get("resume_from", 0)

        if self.on_status:
            if resume_from > 0:
                self.on_status(f"Продовжую з {resume_from / (1024**2):.1f} МБ")
            else:
                self.on_status("Передача розпочата...")

        # ── Stream file chunks ─────────────────────────────────────
        sent = resume_from
        t0 = time.monotonic()
        last_progress_time = t0

        with open(self.filepath, "rb") as f:
            if resume_from > 0:
                f.seek(resume_from)

            while sent < file_size:
                if self._cancelled:
                    return False

                to_read = min(TCP_CHUNK_SIZE, file_size - sent)
                chunk = f.read(to_read)
                if not chunk:
                    break

                _send_msg(self.sock, self.crypto, chunk)
                sent += len(chunk)

                now = time.monotonic()
                if self.on_progress and (now - last_progress_time >= 0.1):
                    elapsed = now - t0
                    speed = (sent - resume_from) / elapsed if elapsed > 0 else 0
                    self.on_progress(sent, file_size, speed)
                    last_progress_time = now

        # Final progress
        if self.on_progress:
            elapsed = time.monotonic() - t0
            speed = (sent - resume_from) / elapsed if elapsed > 0 else 0
            self.on_progress(sent, file_size, speed)

        # ── Wait for completion ACK ────────────────────────────────
        done_raw = _recv_msg(self.sock, self.crypto)
        done = json.loads(done_raw)

        if done.get("verified"):
            if self.on_status:
                self.on_status("Файл передано та перевірено! ✓")
            return True
        else:
            if self.on_status:
                self.on_status("Помилка: отримувач не підтвердив цілісність ✗")
            return False


class TCPReceiver:
    """Receive a file over an established TCP connection."""

    def __init__(
        self,
        sock: socket.socket,
        save_dir: str | Path,
        crypto: CryptoSession,
        on_progress: Optional[ProgressCB] = None,
        on_status: Optional[StatusCB] = None,
    ):
        self.sock = sock
        self.save_dir = Path(save_dir)
        self.crypto = crypto
        self.on_progress = on_progress
        self.on_status = on_status
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def receive(self) -> Optional[Path]:
        """Receive the file. Returns path to saved file or None."""
        # ── Receive metadata ───────────────────────────────────────
        meta_raw = _recv_msg(self.sock, self.crypto)
        meta = json.loads(meta_raw)

        file_name: str = meta["name"]
        file_size: int = meta["size"]
        file_hash: str = meta["sha256"]

        if self.on_status:
            size_mb = file_size / (1024 ** 2)
            if size_mb >= 1024:
                size_str = f"{size_mb / 1024:.1f} ГБ"
            else:
                size_str = f"{size_mb:.1f} МБ"
            self.on_status(f"Отримую: {file_name} ({size_str})")

        save_path = self.save_dir / file_name
        temp_path = save_path.with_suffix(save_path.suffix + ".part")

        # ── Check for partial download (resume) ───────────────────
        resume_from = 0
        if temp_path.exists():
            resume_from = temp_path.stat().st_size

        ack = json.dumps({"type": "meta_ack", "resume_from": resume_from}).encode()
        _send_msg(self.sock, self.crypto, ack)

        # ── Receive chunks ─────────────────────────────────────────
        received = resume_from
        t0 = time.monotonic()
        last_progress_time = t0
        mode = "ab" if resume_from > 0 else "wb"

        with open(temp_path, mode) as f:
            while received < file_size:
                if self._cancelled:
                    return None

                chunk = _recv_msg(self.sock, self.crypto)
                f.write(chunk)
                received += len(chunk)

                now = time.monotonic()
                if self.on_progress and (now - last_progress_time >= 0.1):
                    elapsed = now - t0
                    speed = (received - resume_from) / elapsed if elapsed > 0 else 0
                    self.on_progress(received, file_size, speed)
                    last_progress_time = now

        # Final progress
        if self.on_progress:
            elapsed = time.monotonic() - t0
            speed = (received - resume_from) / elapsed if elapsed > 0 else 0
            self.on_progress(received, file_size, speed)

        # ── Verify hash ────────────────────────────────────────────
        if self.on_status:
            self.on_status("Перевірка цілісності...")
        actual_hash = _sha256_file(temp_path)
        verified = actual_hash == file_hash

        done = json.dumps({"type": "done_ack", "verified": verified}).encode()
        _send_msg(self.sock, self.crypto, done)

        if verified:
            # Rename temp → final
            if save_path.exists():
                save_path.unlink()
            temp_path.rename(save_path)
            if self.on_status:
                self.on_status(f"Збережено: {save_path} ✓")
            return save_path
        else:
            if self.on_status:
                self.on_status("Помилка: хеш не збігається! ✗")
            temp_path.unlink(missing_ok=True)
            return None


# ════════════════════════════════════════════════════════════════════
#  Reliable UDP file transfer
# ════════════════════════════════════════════════════════════════════
#
#  Packet format:
#    [1 byte type][4 bytes seq][payload]
#
#  Types:
#    0x01 DATA   – file data chunk
#    0x02 ACK    – cumulative acknowledgement (payload = 4-byte ack_seq)
#    0x03 META   – file metadata (JSON)
#    0x04 META_ACK – metadata acknowledged
#    0x05 DONE   – transfer complete
#    0x06 DONE_ACK – transfer complete ack
#    0x07 ERROR  – error message
#

_UDP_DATA = 0x01
_UDP_ACK = 0x02
_UDP_META = 0x03
_UDP_META_ACK = 0x04
_UDP_DONE = 0x05
_UDP_DONE_ACK = 0x06
_UDP_ERROR = 0x07


def _udp_pack(ptype: int, seq: int, payload: bytes = b"") -> bytes:
    return struct.pack("!BI", ptype, seq) + payload


def _udp_unpack(data: bytes) -> tuple[int, int, bytes]:
    ptype, seq = struct.unpack_from("!BI", data, 0)
    payload = data[5:]
    return ptype, seq, payload


class UDPSender:
    """Reliable UDP file sender with sliding window."""

    def __init__(
        self,
        sock: socket.socket,
        peer_addr: tuple[str, int],
        filepath: str | Path,
        crypto: CryptoSession,
        on_progress: Optional[ProgressCB] = None,
        on_status: Optional[StatusCB] = None,
    ):
        self.sock = sock
        self.peer_addr = peer_addr
        self.filepath = Path(filepath)
        self.crypto = crypto
        self.on_progress = on_progress
        self.on_status = on_status
        self._cancelled = False
        self.sock.settimeout(0.5)

    def cancel(self):
        self._cancelled = True

    def send(self) -> bool:
        file_size = self.filepath.stat().st_size
        file_name = self.filepath.name

        if self.on_status:
            self.on_status(f"Обчислюю хеш {file_name}...")
        file_hash = _sha256_file(self.filepath)

        # ── Send metadata ──────────────────────────────────────────
        meta = json.dumps({
            "name": file_name, "size": file_size, "sha256": file_hash,
        }).encode()
        meta_enc = self.crypto.encrypt(meta)
        pkt = _udp_pack(_UDP_META, 0, meta_enc)

        if self.on_status:
            self.on_status("Відправляю метадані...")

        # Reliable send of META
        for attempt in range(30):
            if self._cancelled:
                return False
            self.sock.sendto(pkt, self.peer_addr)
            try:
                data, addr = self.sock.recvfrom(65535)
                ptype, seq, payload = _udp_unpack(data)
                if ptype == _UDP_META_ACK:
                    break
            except socket.timeout:
                continue
        else:
            if self.on_status:
                self.on_status("Таймаут: отримувач не відповів")
            return False

        if self.on_status:
            self.on_status("Передача розпочата (UDP)...")

        # ── Sliding window transfer ────────────────────────────────
        total_chunks = (file_size + UDP_PAYLOAD_SIZE - 1) // UDP_PAYLOAD_SIZE
        base_seq = 0  # lowest unacked
        next_seq = 0  # next to send
        window = UDP_WINDOW_SIZE
        sent_packets: dict[int, bytes] = {}  # seq → encrypted packet
        sent_times: dict[int, float] = {}
        all_sent = False

        t0 = time.monotonic()
        last_progress = t0
        bytes_acked = 0

        with open(self.filepath, "rb") as f:
            while base_seq < total_chunks:
                if self._cancelled:
                    return False

                # Send packets within the window
                while next_seq < total_chunks and next_seq < base_seq + window:
                    if next_seq not in sent_packets:
                        offset = next_seq * UDP_PAYLOAD_SIZE
                        f.seek(offset)
                        chunk = f.read(UDP_PAYLOAD_SIZE)
                        enc_chunk = self.crypto.encrypt(chunk)
                        pkt = _udp_pack(_UDP_DATA, next_seq, enc_chunk)
                        sent_packets[next_seq] = pkt
                    try:
                        self.sock.sendto(sent_packets[next_seq], self.peer_addr)
                        sent_times[next_seq] = time.monotonic()
                    except OSError:
                        pass
                    next_seq += 1

                # Wait for ACKs
                try:
                    data, addr = self.sock.recvfrom(65535)
                    ptype, ack_seq, _ = _udp_unpack(data)
                    if ptype == _UDP_ACK and ack_seq >= base_seq:
                        # Remove acked packets from buffer
                        for s in list(sent_packets.keys()):
                            if s <= ack_seq:
                                sent_packets.pop(s, None)
                                sent_times.pop(s, None)
                        base_seq = ack_seq + 1
                        bytes_acked = min(base_seq * UDP_PAYLOAD_SIZE, file_size)
                except socket.timeout:
                    # Retransmit oldest unacked
                    now = time.monotonic()
                    for s in sorted(sent_times.keys()):
                        if now - sent_times[s] > 1.0:
                            if s in sent_packets:
                                try:
                                    self.sock.sendto(sent_packets[s], self.peer_addr)
                                    sent_times[s] = now
                                except OSError:
                                    pass
                            break

                now = time.monotonic()
                if self.on_progress and (now - last_progress >= 0.2):
                    elapsed = now - t0
                    speed = bytes_acked / elapsed if elapsed > 0 else 0
                    self.on_progress(bytes_acked, file_size, speed)
                    last_progress = now

        # ── Send DONE ──────────────────────────────────────────────
        done_pkt = _udp_pack(_UDP_DONE, total_chunks, self.crypto.encrypt(file_hash.encode()))
        for _ in range(20):
            if self._cancelled:
                return False
            self.sock.sendto(done_pkt, self.peer_addr)
            try:
                data, _ = self.sock.recvfrom(65535)
                ptype, seq, payload = _udp_unpack(data)
                if ptype == _UDP_DONE_ACK:
                    verified = self.crypto.decrypt(payload) == b"OK"
                    if self.on_status:
                        if verified:
                            self.on_status("Файл передано та перевірено! ✓")
                        else:
                            self.on_status("Помилка верифікації на стороні отримувача ✗")
                    if self.on_progress:
                        elapsed = time.monotonic() - t0
                        speed = file_size / elapsed if elapsed > 0 else 0
                        self.on_progress(file_size, file_size, speed)
                    return verified
            except socket.timeout:
                continue

        if self.on_status:
            self.on_status("Таймаут при завершенні передачі ✗")
        return False


class UDPReceiver:
    """Reliable UDP file receiver."""

    def __init__(
        self,
        sock: socket.socket,
        peer_addr: tuple[str, int],
        save_dir: str | Path,
        crypto: CryptoSession,
        on_progress: Optional[ProgressCB] = None,
        on_status: Optional[StatusCB] = None,
    ):
        self.sock = sock
        self.peer_addr = peer_addr
        self.save_dir = Path(save_dir)
        self.crypto = crypto
        self.on_progress = on_progress
        self.on_status = on_status
        self._cancelled = False
        self.sock.settimeout(2.0)

    def cancel(self):
        self._cancelled = True

    def receive(self) -> Optional[Path]:
        # ── Wait for metadata ──────────────────────────────────────
        if self.on_status:
            self.on_status("Чекаю метадані від відправника...")

        meta = None
        for _ in range(60):  # wait up to ~120 seconds
            if self._cancelled:
                return None
            try:
                data, addr = self.sock.recvfrom(65535)
                ptype, seq, payload = _udp_unpack(data)
                if ptype == _UDP_META:
                    meta_raw = self.crypto.decrypt(payload)
                    meta = json.loads(meta_raw)
                    # Send META_ACK
                    ack = _udp_pack(_UDP_META_ACK, 0)
                    for _ in range(3):
                        self.sock.sendto(ack, self.peer_addr)
                    break
            except socket.timeout:
                continue

        if meta is None:
            if self.on_status:
                self.on_status("Таймаут: метадані не отримано")
            return None

        file_name = meta["name"]
        file_size = meta["size"]
        file_hash = meta["sha256"]

        if self.on_status:
            size_mb = file_size / (1024 ** 2)
            if size_mb >= 1024:
                self.on_status(f"Отримую: {file_name} ({size_mb / 1024:.1f} ГБ)")
            else:
                self.on_status(f"Отримую: {file_name} ({size_mb:.1f} МБ)")

        save_path = self.save_dir / file_name
        temp_path = save_path.with_suffix(save_path.suffix + ".part")

        total_chunks = (file_size + UDP_PAYLOAD_SIZE - 1) // UDP_PAYLOAD_SIZE

        # ── Receive data chunks ────────────────────────────────────
        received_chunks: dict[int, bytes] = {}
        highest_contiguous = -1  # highest seq where all 0..seq are received
        t0 = time.monotonic()
        last_progress = t0
        last_ack = t0
        done_received = False
        done_hash_payload = b""

        while not done_received:
            if self._cancelled:
                return None

            try:
                data, addr = self.sock.recvfrom(65535)
                ptype, seq, payload = _udp_unpack(data)

                if ptype == _UDP_DATA:
                    if seq not in received_chunks:
                        decrypted = self.crypto.decrypt(payload)
                        received_chunks[seq] = decrypted

                    # Update highest contiguous
                    while highest_contiguous + 1 in received_chunks:
                        highest_contiguous += 1

                elif ptype == _UDP_DONE:
                    done_received = True
                    done_hash_payload = payload

                elif ptype == _UDP_META:
                    # Retransmitted META — re-send ACK
                    ack = _udp_pack(_UDP_META_ACK, 0)
                    self.sock.sendto(ack, self.peer_addr)
                    continue

            except socket.timeout:
                pass

            # Send periodic ACK
            now = time.monotonic()
            if now - last_ack >= 0.05:
                ack = _udp_pack(_UDP_ACK, highest_contiguous)
                try:
                    self.sock.sendto(ack, self.peer_addr)
                except OSError:
                    pass
                last_ack = now

            if self.on_progress and (now - last_progress >= 0.2):
                bytes_done = min((highest_contiguous + 1) * UDP_PAYLOAD_SIZE, file_size)
                elapsed = now - t0
                speed = bytes_done / elapsed if elapsed > 0 else 0
                self.on_progress(bytes_done, file_size, speed)
                last_progress = now

        # Send final ACK for all data
        ack = _udp_pack(_UDP_ACK, total_chunks - 1)
        for _ in range(5):
            try:
                self.sock.sendto(ack, self.peer_addr)
            except OSError:
                pass

        # ── Write file ─────────────────────────────────────────────
        if self.on_status:
            self.on_status("Записую файл...")

        with open(temp_path, "wb") as f:
            for seq in range(total_chunks):
                if seq in received_chunks:
                    f.write(received_chunks[seq])
                else:
                    if self.on_status:
                        self.on_status(f"Помилка: відсутній чанк #{seq}")
                    return None

        received_chunks.clear()  # free memory

        # ── Verify ─────────────────────────────────────────────────
        if self.on_status:
            self.on_status("Перевірка цілісності...")
        actual_hash = _sha256_file(temp_path)

        # Also check hash from DONE packet
        try:
            sender_hash = self.crypto.decrypt(done_hash_payload).decode()
        except Exception:
            sender_hash = ""

        verified = actual_hash == file_hash and actual_hash == sender_hash

        # Send DONE_ACK
        result = b"OK" if verified else b"FAIL"
        done_ack = _udp_pack(_UDP_DONE_ACK, 0, self.crypto.encrypt(result))
        for _ in range(5):
            try:
                self.sock.sendto(done_ack, self.peer_addr)
            except OSError:
                pass

        if verified:
            if save_path.exists():
                save_path.unlink()
            temp_path.rename(save_path)
            if self.on_status:
                self.on_status(f"Збережено: {save_path} ✓")
            if self.on_progress:
                elapsed = time.monotonic() - t0
                speed = file_size / elapsed if elapsed > 0 else 0
                self.on_progress(file_size, file_size, speed)
            return save_path
        else:
            if self.on_status:
                self.on_status("Помилка: хеш не збігається! ✗")
            temp_path.unlink(missing_ok=True)
            return None
