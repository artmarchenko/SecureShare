"""
SecureShare — VPS WebSocket relay transfer.

Both sender and receiver connect to the same VPS relay server:
  wss://secureshare-relay.duckdns.org

The server pairs clients by session code and pipes raw bytes.
All data is E2E encrypted — the server never inspects content.

Protocol phases:
  1. Key Exchange + Version Negotiation (signaling-encrypted)
     Both sides send X25519 public key + protocol_version + app_version.
     Optionally includes reconnect_token for auto-reconnect.
     If versions are incompatible → clear error message → abort.
  2. Verification (signaling-encrypted)
     Both sides confirm verification code matches (user interaction).
     On auto-reconnect: skipped if reconnect_token matches.
  3. File Transfer (E2E encrypted with derived key)
     Sender: metadata → chunks → done
     Receiver: meta_ack → done_ack (with SHA-256 result)

     Resume support (v3.1):
       After receiving relay_meta, the receiver checks for a matching
       .resume manifest from a previous interrupted transfer.  If found,
       relay_meta_ack includes resume=true + received_chunks list.
       The sender then skips already-received chunks.

     Auto-reconnect (v3.2):
       On connection loss during transfer, both sides automatically
       reconnect with the same session code, re-do key exchange,
       skip verification (reconnect_token proves identity), and
       resume the transfer.

Wire format:
  [1 byte type][payload]

  'S' (0x53)  signaling : signaling_encrypt(JSON)
  'C' (0x43)  control   : e2e_encrypt(JSON)
  'D' (0x44)  data      : [4B seq BE] e2e_encrypt(compressed_chunk)

Control message types (JSON field "type"):
  relay_meta        sender → receiver   file info (+ transfer_id)
  relay_meta_ack    receiver → sender   ready to receive (+ resume info)
  relay_done        sender → receiver   all chunks sent
  relay_done_ack    receiver → sender   SHA-256 result
  relay_retransmit  receiver → sender   list of missing chunk indices
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import queue
import socket
import struct
import threading
import time
import zlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger(__name__)

try:
    import websocket          # websocket-client (sync API)
    _HAS_WS = True
except ImportError:
    _HAS_WS = False


def _is_dns_error(exc: Exception) -> bool:
    """Return True if the exception is a DNS resolution failure (transient)."""
    # socket.gaierror is the canonical DNS error
    if isinstance(exc, socket.gaierror):
        return True
    # websocket-client wraps it; check the string as well
    msg = str(exc).lower()
    return "getaddrinfo" in msg or "name or service not known" in msg


from .config import (
    VPS_RELAY_URL,
    VPS_CHUNK_SIZE,
    VPS_MAX_FILE_SIZE,
    APP_VERSION,
    PROTOCOL_VERSION,
    MIN_PROTOCOL_VERSION,
    RESUME_MANIFEST_EXT,
    RESUME_MAX_AGE,
    RESUME_SAVE_INTERVAL,
    RECONNECT_MAX_RETRIES,
    RECONNECT_BASE_DELAY,
    RECONNECT_MAX_DELAY,
)
from .i18n import t
from .format import human_size
from .crypto_utils import (
    CryptoSession,
    derive_signaling_key,
    signaling_encrypt,
    signaling_decrypt,
)


class TransferState(str, Enum):
    """Coarse transfer phase, reported to the UI via `on_state`."""
    CONNECTING   = "connecting"
    WAITING      = "waiting"
    KEY_EXCHANGE = "key_exchange"
    VERIFYING    = "verifying"
    TRANSFERRING = "transferring"
    DONE         = "done"
    ERROR        = "error"


ProgressCB = Callable[[int, int, float], None]
StatusCB   = Callable[[str], None]
StateCB    = Callable[[TransferState], None]
VerifyCB   = Callable[[str], bool]   # verification_code → user_confirmed
EmitCB     = Callable[..., None]     # emit(message_key, **format_args)

_S = TransferState
# Which status message moves the transfer into which phase. Messages not
# listed here are informational and leave the phase unchanged.
_STATE_FOR_MESSAGE: dict[str, TransferState] = {
    # connecting / waiting
    "relay_connecting_to":       _S.CONNECTING,
    "relay_reconnecting_to":     _S.CONNECTING,
    "relay_waiting_receiver":    _S.WAITING,
    "relay_waiting_sender":      _S.WAITING,
    "relay_waiting_meta":        _S.WAITING,
    "relay_waiting_meta_ack":    _S.WAITING,
    "relay_waiting_integrity":   _S.WAITING,
    # handshake
    "relay_key_exchange":        _S.KEY_EXCHANGE,
    "relay_verify_code":         _S.VERIFYING,
    # data
    "relay_sending":             _S.TRANSFERRING,
    "relay_sending_resume":      _S.TRANSFERRING,
    "relay_receiving":           _S.TRANSFERRING,
    "relay_receiving_resume":    _S.TRANSFERRING,
    # outcome
    "relay_file_sent_ok":        _S.DONE,
    "relay_saved":               _S.DONE,
    # errors
    "relay_need_ws":             _S.ERROR,
    "relay_file_read_error":     _S.ERROR,
    "relay_retries_exhausted":   _S.ERROR,
    "relay_connect_error":       _S.ERROR,
    "relay_key_exchange_error":  _S.ERROR,
    "relay_key_format_error":    _S.ERROR,
    "relay_key_decrypt_error":   _S.ERROR,
    "relay_key_message_error":   _S.ERROR,
    "relay_incompatible":        _S.ERROR,
    "relay_auto_verify_error":   _S.ERROR,
    "relay_verify_rejected":     _S.ERROR,
    "relay_verify_error":        _S.ERROR,
    "relay_verify_format_error": _S.ERROR,
    "relay_verify_decrypt_error": _S.ERROR,
    "relay_peer_rejected":       _S.ERROR,
    "relay_verify_msg_error":    _S.ERROR,
    "relay_meta_timeout":        _S.ERROR,
    "relay_meta_unexpected":     _S.ERROR,
    "relay_integrity_timeout":   _S.ERROR,
    "relay_unsafe_filename":     _S.ERROR,
    "relay_path_traversal":      _S.ERROR,
    "relay_invalid_filesize":    _S.ERROR,
    "relay_file_too_large":      _S.ERROR,
    "relay_part_open_error":     _S.ERROR,
    "relay_file_create_error":   _S.ERROR,
    "relay_hash_mismatch_recv":  _S.ERROR,
    "transfer_error_generic":    _S.ERROR,
}
del _S


class _Attempt(Enum):
    """Outcome of one connect-and-transfer attempt."""
    SUCCESS = "success"
    FATAL   = "fatal"     # do not retry (cancel, rejected code, invalid data, ...)
    RETRY   = "retry"     # connection-level problem: reconnect and try again


class _RelayPeer:
    """Behaviour shared by VPSRelaySender and VPSRelayReceiver.

    Subclasses set `_ROLE` / `_WAITING_KEY` and implement one attempt; this
    base class owns the reconnect loop, the session handshake and cancel.
    """

    _ROLE = "Peer"
    _WAITING_KEY = ""          # status message shown while waiting for the peer

    def __init__(
        self,
        session_code: str,
        on_progress: Optional[ProgressCB],
        on_status: Optional[StatusCB],
        on_verify: Optional[VerifyCB],
        on_state: Optional[StateCB],
    ) -> None:
        self._code       = session_code
        self.on_progress = on_progress
        self.on_status   = on_status
        self.on_state    = on_state
        self.on_verify   = on_verify or (lambda code: True)
        self._cancelled  = False
        self._cancel_event = threading.Event()
        self._ws: Optional[websocket.WebSocket] = None
        self._crypto: Optional[CryptoSession] = None
        self._reconnect_token: Optional[str] = None

    # ── Public ────────────────────────────────────────────────────

    def cancel(self) -> None:
        self._cancelled = True
        self._cancel_event.set()
        self._close()

    # ── Status reporting ──────────────────────────────────────────

    def _emit(self, key: str, **fmt) -> None:
        """Log a translated status message and report the phase it implies."""
        msg = t(key, **fmt)
        log.info("[%s] %s", self._ROLE, msg)
        if self.on_status:
            self.on_status(msg)
        state = _STATE_FOR_MESSAGE.get(key)
        if state is not None and self.on_state:
            self.on_state(state)

    # ── Reconnect loop ────────────────────────────────────────────

    def _run_with_reconnect(self, attempt: Callable[[bool], tuple], failure):
        """Call `attempt(is_reconnect)` until it succeeds, fails for good,
        or RECONNECT_MAX_RETRIES reconnects are used up.

        `attempt` returns (_Attempt, value); `value` is returned on SUCCESS,
        `failure` otherwise.
        """
        for n in range(RECONNECT_MAX_RETRIES + 1):
            if self._cancelled:
                return failure
            if n > 0 and not self._backoff(n):
                return failure
            self._before_attempt()
            try:
                outcome, value = attempt(n > 0)
                if outcome is _Attempt.SUCCESS:
                    return value
                if outcome is _Attempt.FATAL or self._cancelled:
                    return failure
                self._emit("relay_connection_lost")
            except Exception as exc:
                self._emit("transfer_error_generic", error=str(exc))
                log.exception("%s error", type(self).__name__)
            finally:
                self._close()
        self._emit("relay_retries_exhausted")
        return failure

    def _backoff(self, n: int) -> bool:
        """Wait before reconnect attempt `n`. Returns False if cancelled."""
        delay = min(RECONNECT_BASE_DELAY * 2 ** (n - 1), RECONNECT_MAX_DELAY)
        self._emit("relay_reconnecting", delay=f"{delay:.0f}", attempt=n, max=RECONNECT_MAX_RETRIES)
        return not self._cancel_event.wait(delay)

    def _before_attempt(self) -> None:
        """Hook: reset per-attempt state."""

    # ── Session setup (connect → key exchange → verification) ─────

    def _open_session(self, is_reconnect: bool) -> Optional[_Attempt]:
        """Connect to the relay and establish a verified E2E session.

        Returns None on success, otherwise how the attempt should end.
        """
        self._emit("relay_reconnecting_to" if is_reconnect else "relay_connecting_to")
        try:
            self._ws = websocket.WebSocket()
            self._ws.connect(VPS_RELAY_URL, timeout=30)
            self._ws.settimeout(300)       # 5 min to wait for the peer
            self._ws.send(self._code)      # register session code
        except Exception as exc:
            self._emit("relay_connect_error", error=str(exc))
            # DNS failures are transient — always allow retry
            if is_reconnect or _is_dns_error(exc):
                return _Attempt.RETRY
            return _Attempt.FATAL

        self._emit(self._WAITING_KEY)

        self._crypto, peer_token = _do_key_exchange(
            self._ws, self._code, self._emit,
            reconnect_token=self._reconnect_token,
        )
        if not self._crypto:
            return _Attempt.RETRY if is_reconnect else _Attempt.FATAL

        # Token for the *next* reconnect comes from this new key exchange
        new_token = _make_reconnect_token(self._crypto, self._code)
        sig_key = derive_signaling_key(self._code)
        self._ws.settimeout(120)

        # Auto-verify on reconnect if the peer proved the previous session
        # (timing-safe comparison to prevent side-channel leaks)
        auto_verify = (
            is_reconnect
            and self._reconnect_token is not None
            and peer_token is not None
            and hmac.compare_digest(peer_token, self._reconnect_token)
        )
        if not _do_verification(
            self._ws, self._crypto, sig_key,
            self.on_verify, self._emit,
            auto_verify=auto_verify,
        ):
            return _Attempt.FATAL          # verification rejected

        self._reconnect_token = new_token
        return None

    def _close(self) -> None:
        try:
            if self._ws:
                self._ws.close()
        except Exception:
            pass


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


def _make_transfer_id(name: str, size: int, sha256: str) -> str:
    """Deterministic transfer ID from file metadata.

    Two independent sessions for the same file produce the same ID,
    enabling the receiver to detect a resumable partial download.
    """
    raw = f"{name}|{size}|{sha256}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


# ── Reconnect token ──────────────────────────────────────────────

def _make_reconnect_token(crypto: CryptoSession, session_code: str) -> str:
    """Derive a reconnect token from the DH shared key.

    Both peers compute the same token after key exchange.  On
    reconnect, including this token in the key-exchange message
    proves that the peer participated in the original session
    → verification popup can be safely skipped.
    """
    raw = crypto.mac(session_code.encode() + b"secureshare-reconnect-v1")[:16]
    return base64.b64encode(raw).decode()


# ── Resume manifest helpers ───────────────────────────────────────

def _manifest_path(save_dir: Path, file_name: str) -> Path:
    """Return the path to the .resume manifest for a given file."""
    return save_dir / (file_name + ".part" + RESUME_MANIFEST_EXT)


def _save_manifest(
    path: Path,
    transfer_id: str,
    file_name: str,
    file_size: int,
    file_sha256: str,
    chunk_size: int,
    total_chunks: int,
    received_chunks: set[int],
) -> None:
    """Persist the resume manifest to disk (atomic write)."""
    data = {
        "transfer_id":    transfer_id,
        "file_name":      file_name,
        "file_size":      file_size,
        "file_sha256":    file_sha256,
        "chunk_size":     chunk_size,
        "total_chunks":   total_chunks,
        "received_chunks": sorted(received_chunks),
        "timestamp":      time.time(),
    }
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        tmp.replace(path)
    except Exception as exc:
        log.debug("Failed to save resume manifest: %s", exc)
        tmp.unlink(missing_ok=True)


def _load_manifest(
    save_dir: Path, file_name: str, transfer_id: str
) -> Optional[dict]:
    """Load a matching resume manifest if it exists and is still valid.

    Returns manifest dict with 'received_chunks' as a set, or None.
    """
    mpath = _manifest_path(save_dir, file_name)
    if not mpath.exists():
        return None
    try:
        with open(mpath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        mpath.unlink(missing_ok=True)
        return None

    # Validate transfer_id and age
    if data.get("transfer_id") != transfer_id:
        log.info("Resume manifest transfer_id mismatch — ignoring")
        return None

    age = time.time() - data.get("timestamp", 0)
    if age > RESUME_MAX_AGE:
        log.info("Resume manifest too old (%.0f h) — ignoring", age / 3600)
        mpath.unlink(missing_ok=True)
        return None

    # Convert list → set for fast lookup
    data["received_chunks"] = set(data.get("received_chunks", []))
    return data


def _delete_manifest(save_dir: Path, file_name: str) -> None:
    """Remove the .resume manifest file."""
    mpath = _manifest_path(save_dir, file_name)
    mpath.unlink(missing_ok=True)


# ── File name safety ──────────────────────────────────────────────

_WIN_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def _safe_file_name(raw: object) -> Optional[str]:
    """Turn the file name announced by the peer into a safe local name.

    Keeps only the last path component (treating both '/' and '\\' as
    separators on every OS), replaces characters that are special on
    Windows (':' would create an NTFS alternate data stream), and avoids
    reserved device names. Returns None if nothing usable is left.
    """
    if not isinstance(raw, str) or "\x00" in raw:
        return None
    name = raw.replace("\\", "/").split("/")[-1]
    name = "".join("_" if ord(ch) < 32 or ch in ':*?"<>|' else ch for ch in name)
    name = name.strip().rstrip(". ")          # Windows drops trailing dots/spaces
    if not name or name in (".", ".."):
        return None
    if name.split(".")[0].upper() in _WIN_RESERVED_NAMES:
        name = "_" + name
    return name[:255]


def _unique_path(path: Path) -> Path:
    """Return `path`, or 'name (1).ext', 'name (2).ext', ... if it exists."""
    if not path.exists():
        return path
    for n in range(1, 10_000):
        candidate = path.with_name(f"{path.stem} ({n}){path.suffix}")
        if not candidate.exists():
            return candidate
    raise FileExistsError(f"too many files named like {path.name}")


# ── Key Exchange (common for sender and receiver) ─────────────────

def _do_key_exchange(
    ws,
    session_code: str,
    emit: EmitCB,
    reconnect_token: Optional[str] = None,
) -> tuple[Optional[CryptoSession], Optional[str]]:
    """
    Perform X25519 key exchange over the WebSocket with version negotiation.

    Both sides send their public key + protocol version simultaneously
    (signaling-encrypted).  The VPS relay pipes A→B and B→A, so each
    side receives the other's key.

    If reconnect_token is provided, it is included in the signaling
    message so the peer can verify the reconnect without a popup.

    Returns (CryptoSession, peer_reconnect_token) or (None, None).
    """
    crypto = CryptoSession(session_code)
    sig_key = derive_signaling_key(session_code)

    # Send our public key + version info + optional reconnect token
    pub_key_b64 = base64.b64encode(crypto.get_public_key_bytes()).decode()
    msg: dict = {
        "type":             "pub_key",
        "key":              pub_key_b64,
        "protocol_version": PROTOCOL_VERSION,
        "app_version":      APP_VERSION,
    }
    if reconnect_token:
        msg["reconnect_token"] = reconnect_token

    sig_payload = json.dumps(msg).encode()
    ws.send_binary(bytes([_SIG]) + signaling_encrypt(sig_key, sig_payload))

    emit("relay_key_exchange")

    # Receive peer's public key (blocks until peer connects + sends)
    try:
        raw = ws.recv()
    except Exception as e:
        emit("relay_key_exchange_error", error=str(e))
        return None, None

    if not raw or not isinstance(raw, bytes) or len(raw) < 2 or raw[0] != _SIG:
        emit("relay_key_format_error")
        return None, None

    try:
        peer_msg = json.loads(signaling_decrypt(sig_key, raw[1:]))
    except Exception:
        emit("relay_key_decrypt_error")
        return None, None

    if peer_msg.get("type") != "pub_key" or "key" not in peer_msg:
        emit("relay_key_message_error")
        return None, None

    # ── Version compatibility check ─────────────────────────────
    peer_proto = peer_msg.get("protocol_version", 0)
    peer_app   = peer_msg.get("app_version", "unknown")

    log.info(
        "Version negotiation: us=proto%d/app%s, peer=proto%d/app%s",
        PROTOCOL_VERSION, APP_VERSION, peer_proto, peer_app,
    )
    emit("relay_protocol_info",
         our_proto=PROTOCOL_VERSION, peer_proto=peer_proto,
         our_app=APP_VERSION, peer_app=peer_app)

    if peer_proto < MIN_PROTOCOL_VERSION:
        emit("relay_incompatible",
             peer_proto=peer_proto, min_proto=MIN_PROTOCOL_VERSION)
        return None, None

    if PROTOCOL_VERSION < peer_proto:
        # Peer requires a newer protocol — we might be too old
        log.warning(
            "Peer has newer protocol version (%d > %d). "
            "Consider updating the app.",
            peer_proto, PROTOCOL_VERSION,
        )
        emit("relay_peer_newer", peer_app=peer_app)

    # ── Derive shared key ───────────────────────────────────────
    peer_pub_key = base64.b64decode(peer_msg["key"])
    crypto.derive_shared_key(peer_pub_key)

    peer_reconnect_token = peer_msg.get("reconnect_token")
    return crypto, peer_reconnect_token


def _do_verification(
    ws,
    crypto: CryptoSession,
    sig_key: bytes,
    on_verify: VerifyCB,
    emit: EmitCB,
    auto_verify: bool = False,
) -> bool:
    """
    Show verification code and exchange confirmation with peer.

    If auto_verify is True (reconnect scenario), skip the user popup
    and auto-confirm.  Both sides still exchange 'verified' messages.

    Returns True if both sides verified successfully.
    """
    verification_code = crypto.get_verification_code()

    if auto_verify:
        emit("relay_auto_verify")
        # Send confirmation without user interaction
        confirm_payload = json.dumps({"type": "verified"}).encode()
        ws.send_binary(bytes([_SIG]) + signaling_encrypt(sig_key, confirm_payload))

        try:
            raw = ws.recv()
        except Exception as e:
            emit("relay_auto_verify_error", error=str(e))
            return False

        if not raw or not isinstance(raw, bytes) or len(raw) < 2 or raw[0] != _SIG:
            return False

        try:
            peer_msg = json.loads(signaling_decrypt(sig_key, raw[1:]))
        except Exception:
            return False

        if peer_msg.get("type") == "verified":
            emit("relay_auto_verify_ok")
            return True
        return False

    # ── Normal verification (user interaction) ────────────────
    emit("relay_verify_code", code=verification_code)

    # Ask user to verify
    if not on_verify(verification_code):
        # User rejected — notify peer
        reject_payload = json.dumps({"type": "verify_reject"}).encode()
        try:
            ws.send_binary(bytes([_SIG]) + signaling_encrypt(sig_key, reject_payload))
        except Exception:
            pass
        emit("relay_verify_rejected")
        return False

    # Send verification confirmation
    confirm_payload = json.dumps({"type": "verified"}).encode()
    ws.send_binary(bytes([_SIG]) + signaling_encrypt(sig_key, confirm_payload))

    emit("relay_verify_confirmed")

    # Wait for peer's verification
    try:
        raw = ws.recv()
    except Exception as e:
        emit("relay_verify_error", error=str(e))
        return False

    if not raw or not isinstance(raw, bytes) or len(raw) < 2 or raw[0] != _SIG:
        emit("relay_verify_format_error")
        return False

    try:
        peer_msg = json.loads(signaling_decrypt(sig_key, raw[1:]))
    except Exception:
        emit("relay_verify_decrypt_error")
        return False

    if peer_msg.get("type") == "verify_reject":
        emit("relay_peer_rejected")
        return False

    if peer_msg.get("type") != "verified":
        emit("relay_verify_msg_error")
        return False

    emit("relay_both_verified")

    return True


# ════════════════════════════════════════════════════════════════════
#  VPSRelaySender
# ════════════════════════════════════════════════════════════════════

class VPSRelaySender(_RelayPeer):
    """
    Send a file through the VPS relay server.

    Handles the entire flow: connect → key exchange → verify → transfer.
    Supports auto-reconnect on connection loss during transfer.
    GUI only needs to provide callbacks for progress, status, and verification.
    """

    _ROLE = "Sender"
    _WAITING_KEY = "relay_waiting_receiver"

    def __init__(
        self,
        session_code: str,
        filepath: str | Path,
        on_progress: Optional[ProgressCB] = None,
        on_status:   Optional[StatusCB]   = None,
        on_verify:   Optional[VerifyCB]   = None,
        on_state:    Optional[StateCB]    = None,
    ):
        super().__init__(session_code, on_progress, on_status, on_verify, on_state)
        self._filepath = Path(filepath)
        self._ctl_queue: queue.Queue = queue.Queue()
        self._connection_lost = threading.Event()

        # Cached file metadata (computed once, reused across reconnects)
        self._file_hash: Optional[str] = None
        self._transfer_id: Optional[str] = None

    def cancel(self) -> None:
        self._connection_lost.set()
        super().cancel()

    # ── Public entry point (with auto-reconnect) ──────────────────

    def send(self) -> bool:
        """
        Connect to VPS, perform key exchange + verification, send file.
        Auto-reconnects on connection loss (up to RECONNECT_MAX_RETRIES).
        Returns True on success, False on failure/cancel.
        """
        if not _HAS_WS:
            self._emit("relay_need_ws")
            return False

        # Pre-compute file metadata once (expensive for large files)
        try:
            file_name = self._filepath.name
            file_size = self._filepath.stat().st_size
            self._emit("relay_computing_hash", filename=file_name)
            self._file_hash = _sha256_file(self._filepath)
            self._transfer_id = _make_transfer_id(
                file_name, file_size, self._file_hash
            )
        except Exception as exc:
            self._emit("relay_file_read_error", error=str(exc))
            return False

        return self._run_with_reconnect(self._send_attempt, failure=False)

    def _before_attempt(self) -> None:
        self._connection_lost.clear()
        self._ctl_queue = queue.Queue()

    def _send_attempt(self, is_reconnect: bool = False) -> tuple[_Attempt, bool]:
        """Single send attempt: (_Attempt, sent_ok)."""
        failed = self._open_session(is_reconnect)
        if failed is not None:
            return failed, False
        result = self._transfer()
        if result is True:
            return _Attempt.SUCCESS, True
        return (_Attempt.RETRY if result is None else _Attempt.FATAL), False

    def _transfer(self) -> Optional[bool]:
        """Send metadata + chunks over an established session.

        Returns True (done), False (permanent failure) or None (connection
        lost — retryable).
        """
        # ── 4. Start background receiver ──────────────────────────
        recv_thread = threading.Thread(target=self._recv_worker, daemon=True)
        recv_thread.start()

        # ── 5. Send metadata ──────────────────────────────────────
        file_name    = self._filepath.name
        file_size    = self._filepath.stat().st_size
        total_chunks = (file_size + VPS_CHUNK_SIZE - 1) // VPS_CHUNK_SIZE

        self._send_ctl(json.dumps({
            "type":         "relay_meta",
            "name":         file_name,
            "size":         file_size,
            "sha256":       self._file_hash,
            "chunk_size":   VPS_CHUNK_SIZE,
            "total_chunks": total_chunks,
            "transfer_id":  self._transfer_id,
        }).encode())

        # Wait for meta ACK (may include resume info)
        self._emit("relay_waiting_meta_ack")
        ack = self._wait_ctl(120)
        if ack is None:
            if self._cancelled:
                return False
            if not self._connection_lost.is_set():
                self._emit("relay_meta_timeout")
            return None  # retryable
        if ack.get("type") != "relay_meta_ack":
            self._emit("relay_meta_unexpected")
            return None

        # ── 5b. Check if receiver requests resume ─────────────────
        skip_chunks: set[int] = set()
        resume_bytes = 0
        if ack.get("resume"):
            already = ack.get("received_chunks", [])
            skip_chunks = set(already)
            resume_bytes = len(skip_chunks) * VPS_CHUNK_SIZE
            if total_chunks - 1 in skip_chunks:
                last_chunk_size = file_size - (total_chunks - 1) * VPS_CHUNK_SIZE
                resume_bytes = resume_bytes - VPS_CHUNK_SIZE + last_chunk_size
            resume_bytes = min(resume_bytes, file_size)
            self._emit("relay_resume_info",
                       received=len(skip_chunks), total=total_chunks,
                       mb=f"{resume_bytes / (1024**2):.1f}")

        # ── 6. Send file chunks ───────────────────────────────────
        size_str = human_size(file_size)
        chunks_to_send = total_chunks - len(skip_chunks)
        if skip_chunks:
            self._emit("relay_sending_resume",
                       filename=file_name, size=size_str, chunks=chunks_to_send)
        else:
            self._emit("relay_sending", filename=file_name, size=size_str)

        t0 = time.monotonic()
        sent_bytes = resume_bytes
        last_prog  = t0

        if self.on_progress and resume_bytes > 0:
            self.on_progress(sent_bytes, file_size, 0)

        with open(self._filepath, "rb") as f:
            for seq in range(total_chunks):
                if self._cancelled:
                    return False
                if self._connection_lost.is_set():
                    return None  # connection lost → retry

                if seq in skip_chunks:
                    f.seek((seq + 1) * VPS_CHUNK_SIZE)
                    continue

                chunk = f.read(VPS_CHUNK_SIZE)
                if not chunk:
                    break
                self._send_dat(seq, chunk)
                sent_bytes += len(chunk)

                now = time.monotonic()
                if self.on_progress and (now - last_prog >= 0.3):
                    elapsed = now - t0
                    speed = (sent_bytes - resume_bytes) / elapsed if elapsed > 0 else 0
                    self.on_progress(sent_bytes, file_size, speed)
                    last_prog = now

        # Final progress
        if self.on_progress:
            elapsed = time.monotonic() - t0
            speed = (sent_bytes - resume_bytes) / elapsed if elapsed > 0 else 0
            self.on_progress(sent_bytes, file_size, speed)

        # ── 7. Send DONE and wait for verification ────────────────
        done_payload = json.dumps({
            "type":         "relay_done",
            "sha256":       self._file_hash,
            "total_chunks": total_chunks,
        }).encode()
        self._send_ctl(done_payload)
        self._emit("relay_waiting_integrity")

        retransmit_rounds = 0
        deadline = time.monotonic() + 600

        while time.monotonic() < deadline and not self._cancelled:
            if self._connection_lost.is_set():
                return None  # connection lost → retry

            msg = self._wait_ctl(10)
            if msg is None:
                if self._cancelled:
                    return False
                if self._connection_lost.is_set():
                    return None
                self._send_ctl(done_payload)
                continue

            if msg.get("type") == "relay_done_ack":
                ok = msg.get("verified", False)
                if ok:
                    self._emit("relay_file_sent_ok")
                else:
                    self._emit("relay_hash_mismatch_sender")
                return ok

            elif msg.get("type") == "relay_retransmit" and retransmit_rounds < 5:
                missing = msg.get("missing", [])
                if not missing:
                    continue
                retransmit_rounds += 1
                self._emit("relay_retransmit",
                           count=len(missing), round=retransmit_rounds)
                with open(self._filepath, "rb") as f:
                    for seq_i in missing:
                        if self._cancelled:
                            return False
                        if self._connection_lost.is_set():
                            return None
                        f.seek(seq_i * VPS_CHUNK_SIZE)
                        chunk = f.read(VPS_CHUNK_SIZE)
                        if chunk:
                            self._send_dat(seq_i, chunk)
                self._send_ctl(done_payload)

        self._emit("relay_integrity_timeout")
        return None  # retryable (might be connection issue)

    # ── Send helpers ───────────────────────────────────────────────

    def _wait_ctl(self, timeout: float) -> Optional[dict]:
        """Wait for the next control message.

        Returns None on timeout, cancel, or lost connection (callers check
        which). Polls in short slices so cancel() takes effect promptly.
        """
        deadline = time.monotonic() + timeout
        while not self._cancelled:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                return self._ctl_queue.get(timeout=min(0.25, remaining))
            except queue.Empty:
                if self._connection_lost.is_set():
                    return None
        return None

    def _send_ctl(self, plaintext: bytes) -> None:
        try:
            self._ws.send_binary(bytes([_CTL]) + self._crypto.encrypt(plaintext))
        except Exception as exc:
            log.debug("VPS send ctl error: %s", exc)
            self._connection_lost.set()

    def _send_dat(self, seq: int, chunk: bytes) -> None:
        try:
            payload = _compress(chunk)
            payload = self._crypto.encrypt(payload)
            frame   = bytes([_DAT]) + struct.pack("!I", seq) + payload
            self._ws.send_binary(frame)
        except Exception as exc:
            log.debug("VPS send dat error: %s", exc)
            self._connection_lost.set()

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
        finally:
            self._connection_lost.set()


# ════════════════════════════════════════════════════════════════════
#  VPSRelayReceiver
# ════════════════════════════════════════════════════════════════════

class VPSRelayReceiver(_RelayPeer):
    """
    Receive a file through the VPS relay server.

    Handles the entire flow: connect → key exchange → verify → receive.
    Supports auto-reconnect on connection loss during transfer.
    GUI only needs to provide callbacks for progress, status, and verification.
    """

    _ROLE = "Receiver"
    _WAITING_KEY = "relay_waiting_sender"

    def __init__(
        self,
        session_code: str,
        save_dir: str | Path,
        on_progress: Optional[ProgressCB] = None,
        on_status:   Optional[StatusCB]   = None,
        on_verify:   Optional[VerifyCB]   = None,
        on_state:    Optional[StateCB]    = None,
    ):
        super().__init__(session_code, on_progress, on_status, on_verify, on_state)
        self._save_dir = Path(save_dir)

    # ── Public entry point (with auto-reconnect) ──────────────────

    def receive(self) -> Optional[Path]:
        """
        Connect to VPS, perform key exchange + verification, receive file.
        Auto-reconnects on connection loss (up to RECONNECT_MAX_RETRIES).
        Returns Path to saved file on success, None on failure/cancel.
        """
        if not _HAS_WS:
            self._emit("relay_need_ws")
            return None
        return self._run_with_reconnect(self._receive_attempt, failure=None)

    def _receive_attempt(self, is_reconnect: bool = False) -> tuple[_Attempt, Optional[Path]]:
        """Single receive attempt: (_Attempt, saved_path)."""
        failed = self._open_session(is_reconnect)
        if failed is not None:
            return failed, None

        self._emit("relay_waiting_meta")
        self._ws.settimeout(120)

        rx = _Incoming()
        try:
            while not self._cancelled:
                try:
                    raw = self._ws.recv()
                except Exception:
                    # Connection lost: worth retrying once data has started to flow
                    retry = rx.file_name and rx.received and not self._cancelled
                    return (_Attempt.RETRY if retry else _Attempt.FATAL), None

                if not raw or not isinstance(raw, bytes):
                    continue

                if raw[0] == _CTL:
                    try:
                        msg = json.loads(self._crypto.decrypt(raw[1:]))
                    except Exception:
                        continue
                    kind = msg.get("type")
                    if kind == "relay_meta":
                        if not self._on_meta(msg, rx):
                            return _Attempt.FATAL, None
                    elif kind == "relay_done":
                        done = self._on_done(msg, rx)
                        if done is not None:
                            return done

                elif raw[0] == _DAT and rx.file_name:
                    self._on_data(raw, rx)

            return _Attempt.FATAL, None        # cancelled

        except Exception as exc:
            self._emit("transfer_error_generic", error=str(exc))
            log.exception("VPSRelayReceiver error")
            retry = rx.file_name and rx.received
            return (_Attempt.RETRY if retry else _Attempt.FATAL), None
        finally:
            if rx.writer:
                rx.writer.close()
            # Save resume manifest on interruption
            if rx.file_name and rx.transfer_id and rx.received and len(rx.received) < rx.total_chunks:
                self._emit("relay_progress_saved", received=len(rx.received), total=rx.total_chunks)
                rx.save_manifest(self._save_dir)

    # ── relay_meta: validate, open .part (resume if possible), ACK ──

    def _on_meta(self, msg: dict, rx: "_Incoming") -> bool:
        """Returns False if the announced file must be refused."""
        file_size    = msg["size"]
        chunk_size   = msg.get("chunk_size", VPS_CHUNK_SIZE)
        total_chunks = msg.get("total_chunks", 0)

        # ── Security: sanitize file name (path traversal) ─
        file_name = _safe_file_name(msg["name"])
        if file_name is None:
            self._emit("relay_unsafe_filename")
            return False
        # Defense-in-depth: verify resolved path stays in save_dir
        resolved = (self._save_dir / file_name).resolve()
        if not str(resolved).startswith(str(self._save_dir.resolve())):
            self._emit("relay_path_traversal")
            return False

        # ── Security: validate file size ──────────────────
        if not isinstance(file_size, int) or file_size <= 0:
            self._emit("relay_invalid_filesize")
            return False
        if file_size > VPS_MAX_FILE_SIZE:
            self._emit("relay_file_too_large",
                       size=f"{file_size / (1024**3):.1f}",
                       limit=f"{VPS_MAX_FILE_SIZE / (1024**3):.0f}")
            return False

        # ── Security: validate chunk_size / total_chunks ──
        if not isinstance(chunk_size, int) or chunk_size <= 0 or chunk_size > 4 * 1024 * 1024:
            chunk_size = VPS_CHUNK_SIZE
        expected_chunks = (file_size + chunk_size - 1) // chunk_size
        if total_chunks != expected_chunks:
            log.warning("total_chunks mismatch: got %r, expected %d", total_chunks, expected_chunks)
            total_chunks = expected_chunks

        rx.file_name    = file_name
        rx.file_size    = file_size
        rx.file_hash    = msg["sha256"]
        rx.transfer_id  = msg.get("transfer_id", "")
        rx.chunk_size   = chunk_size
        rx.total_chunks = total_chunks
        rx.save_path    = self._save_dir / file_name
        rx.temp_path    = rx.save_path.with_suffix(rx.save_path.suffix + ".part")

        # ── Resume detection ──────────────────────
        is_resume = False
        manifest = _load_manifest(self._save_dir, file_name, rx.transfer_id) if rx.transfer_id else None
        if (
            manifest
            and rx.temp_path.exists()
            and manifest.get("chunk_size") == chunk_size
            and manifest.get("total_chunks") == total_chunks
        ):
            try:
                rx.writer = _DiskWriter(rx.temp_path, chunk_size, resume=True)
                is_resume = True
            except Exception as exc:
                self._emit("relay_part_open_error", error=str(exc))
        if is_resume:
            rx.received = manifest["received_chunks"]
            rx.bytes_received = rx.resumed_bytes()
            self._emit("relay_resume_found",
                       received=len(rx.received), total=total_chunks,
                       mb=f"{rx.bytes_received / (1024**2):.1f}")
        else:
            rx.received = set()
            rx.bytes_received = 0
            try:
                rx.writer = _DiskWriter(rx.temp_path, chunk_size, resume=False, size=file_size)
            except Exception as exc:
                self._emit("relay_file_create_error", error=str(exc))
                return False

        size_str = human_size(file_size)
        if is_resume:
            pct = rx.bytes_received / file_size * 100 if file_size else 0
            self._emit("relay_receiving_resume", filename=file_name, size=size_str, pct=f"{pct:.0f}")
        else:
            self._emit("relay_receiving", filename=file_name, size=size_str)

        ack: dict = {"type": "relay_meta_ack"}
        if is_resume and rx.received:
            ack["resume"] = True
            ack["received_chunks"] = sorted(rx.received)
        self._send_ctl(json.dumps(ack).encode())
        rx.t0 = rx.last_progress = time.monotonic()

        if self.on_progress and is_resume:
            self.on_progress(rx.bytes_received, file_size, 0)
        return True

    # ── relay_done: request missing chunks, or verify and save ──────

    def _on_done(self, msg: dict, rx: "_Incoming") -> Optional[tuple[_Attempt, Optional[Path]]]:
        """Returns the attempt's result once finished, None to keep receiving."""
        announced = msg.get("total_chunks", rx.total_chunks)
        if announced != rx.total_chunks:
            # total_chunks was validated against file_size in relay_meta
            log.warning("relay_done total_chunks %r ignored (expected %d)", announced, rx.total_chunks)
        rx.file_hash = msg.get("sha256", rx.file_hash)

        missing = sorted(set(range(rx.total_chunks)) - rx.received)
        if missing:
            if rx.file_name and rx.transfer_id:
                rx.save_manifest(self._save_dir)
            for i in range(0, len(missing), 1000):
                self._send_ctl(json.dumps({"type": "relay_retransmit", "missing": missing[i:i + 1000]}).encode())
            self._emit("relay_request_retransmit", count=len(missing))
            return None

        rx.writer.finish()
        self._emit("relay_verifying_sha")
        verified = _sha256_file(rx.temp_path) == rx.file_hash
        self._send_ctl(json.dumps({"type": "relay_done_ack", "verified": verified}).encode())
        time.sleep(1)

        _delete_manifest(self._save_dir, rx.file_name)
        if not verified:
            self._emit("relay_hash_mismatch_recv")
            rx.temp_path.unlink(missing_ok=True)
            return _Attempt.FATAL, None

        save_path = _unique_path(rx.save_path)
        if save_path != rx.save_path:
            self._emit("relay_file_renamed", filename=save_path.name)
        rx.temp_path.rename(save_path)
        elapsed = time.monotonic() - rx.t0
        avg = rx.file_size / elapsed if elapsed > 0 else 0
        self._emit("relay_saved", filename=save_path.name, speed=f"{avg / (1024*1024):.1f}")
        return _Attempt.SUCCESS, save_path

    # ── data frame: decrypt, queue for disk, persist progress ───────

    def _on_data(self, raw: bytes, rx: "_Incoming") -> None:
        if len(raw) < 5:
            return
        seq = struct.unpack_from("!I", raw, 1)[0]
        if seq not in rx.received:
            try:
                chunk = _decompress(self._crypto.decrypt(raw[5:]))
            except Exception:
                chunk = None
            # A full write queue drops the chunk; it is re-requested later
            if chunk is not None and rx.writer.put(seq, chunk):
                rx.received.add(seq)
                rx.bytes_received += len(chunk)
                rx.chunks_since_save += 1

        if rx.chunks_since_save >= RESUME_SAVE_INTERVAL and rx.transfer_id:
            rx.save_manifest(self._save_dir)
            rx.chunks_since_save = 0

        now = time.monotonic()
        if self.on_progress and rx.file_size and now - rx.last_progress >= 0.5:
            elapsed = now - rx.t0
            self.on_progress(rx.bytes_received, rx.file_size,
                             rx.bytes_received / elapsed if elapsed > 0 else 0)
            rx.last_progress = now

    # ── Send helper ────────────────────────────────────────────────

    def _send_ctl(self, plaintext: bytes) -> None:
        try:
            self._ws.send_binary(bytes([_CTL]) + self._crypto.encrypt(plaintext))
        except Exception as exc:
            log.debug("VPS recv-side send ctl: %s", exc)


# ════════════════════════════════════════════════════════════════════
#  Receiver helpers
# ════════════════════════════════════════════════════════════════════

@dataclass
class _Incoming:
    """State of the file being received during one attempt."""
    file_name:         Optional[str]  = None
    file_size:         int            = 0
    file_hash:         str            = ""
    transfer_id:       str            = ""
    chunk_size:        int            = VPS_CHUNK_SIZE
    total_chunks:      int            = 0
    received:          set            = field(default_factory=set)
    bytes_received:    int            = 0
    chunks_since_save: int            = 0
    save_path:         Optional[Path] = None
    temp_path:         Optional[Path] = None
    writer:            Optional["_DiskWriter"] = None
    t0:                float          = field(default_factory=time.monotonic)
    last_progress:     float          = field(default_factory=time.monotonic)

    def resumed_bytes(self) -> int:
        """Bytes already on disk according to the resume manifest."""
        done = len(self.received) * self.chunk_size
        if self.total_chunks - 1 in self.received:
            last = self.file_size - (self.total_chunks - 1) * self.chunk_size
            done = done - self.chunk_size + last
        return min(done, self.file_size)

    def save_manifest(self, save_dir: Path) -> None:
        _save_manifest(
            _manifest_path(save_dir, self.file_name),
            self.transfer_id, self.file_name, self.file_size,
            self.file_hash, self.chunk_size, self.total_chunks,
            self.received,
        )


class _DiskWriter:
    """Writes received chunks to the .part file on a background thread,
    so disk I/O never stalls the network loop."""

    def __init__(self, path: Path, chunk_size: int, resume: bool, size: int = 0) -> None:
        if resume:
            self._file = open(path, "r+b")
        else:
            self._file = open(path, "w+b")
            if size > 0:                      # pre-allocate
                self._file.seek(size - 1)
                self._file.write(b"\x00")
                self._file.flush()
                self._file.seek(0)
        self._chunk_size = chunk_size
        self._queue: queue.Queue = queue.Queue(maxsize=512)
        self._thread = threading.Thread(target=self._run, daemon=True, name="vps-relay-writer")
        self._thread.start()

    def put(self, seq: int, data: bytes) -> bool:
        """Queue a chunk; False if the queue is full (chunk dropped)."""
        try:
            self._queue.put_nowait((seq, data))
            return True
        except queue.Full:
            return False

    def finish(self) -> None:
        """Write everything queued so far and close the file."""
        self._queue.put(None)
        self._queue.join()
        self._thread.join(timeout=30)
        self._close_file()

    def close(self) -> None:
        """Stop the writer (idempotent; used on every exit path)."""
        if self._thread.is_alive():
            try:
                self._queue.put(None, timeout=5)
            except queue.Full:
                pass
            self._thread.join(timeout=10)
        self._close_file()

    def _run(self) -> None:
        writes = 0
        while True:
            item = self._queue.get()
            if item is None:
                try:
                    if not self._file.closed:
                        self._file.flush()
                except Exception:
                    pass
                self._queue.task_done()
                return
            seq, data = item
            try:
                self._file.seek(seq * self._chunk_size)
                self._file.write(data)
                writes += 1
                if writes % 128 == 0:
                    self._file.flush()
            except Exception:
                pass
            self._queue.task_done()

    def _close_file(self) -> None:
        try:
            self._file.close()
        except Exception:
            pass
