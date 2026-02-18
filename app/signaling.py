"""
SecureShare — signaling for peer discovery.

Strategy:
  1. Connect to ALL MQTT brokers (port 8883/TLS) simultaneously.
  2. Also connect to ntfy.sh via HTTPS (port 443) as fallback — always
     reachable even when MQTT is firewalled.

Both sides publish on every available channel → they meet on whichever
channel(s) they share.

Security:
  - Payloads are AES-256-GCM encrypted with a key derived from the
    session code → eavesdroppers see only ciphertext.
  - MQTT topics and ntfy.sh topics use an HMAC-derived ID → no discovery.
  - MQTT uses TLS (port 8883); ntfy.sh uses HTTPS (port 443).
"""

from __future__ import annotations

import base64
import json
import logging
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import Callable, Optional

import paho.mqtt.client as mqtt

from .config import MQTT_BROKERS, MQTT_PORT, MQTT_TOPIC_PREFIX, MQTT_KEEPALIVE, mqtt_setup_tls
from .crypto_utils import derive_signaling_key, derive_topic_id, signaling_encrypt, signaling_decrypt

log = logging.getLogger(__name__)

# ── SSL context (works inside PyInstaller too) ────────────────────
def _make_ssl_ctx() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


# ════════════════════════════════════════════════════════════════════
#  MQTT connection
# ════════════════════════════════════════════════════════════════════

class _BrokerConn:
    """Single MQTT connection to one broker."""

    def __init__(self, broker: str, topic_sub: str, topic_pub: str,
                 sig_key, on_peer_cb: Callable):
        self.broker = broker
        self._topic_sub = topic_sub
        self._topic_pub = topic_pub
        self._sig_key   = sig_key
        self._on_peer_cb = on_peer_cb
        self.connected   = False
        self._connected_event = threading.Event()

        cid = f"ss-{uuid.uuid4().hex[:8]}"
        self._client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=cid,
        )
        self._client.on_connect    = self._on_connect
        self._client.on_message    = self._on_message
        self._client.on_disconnect = self._on_disconnect

    def connect(self, timeout: float = 10) -> bool:
        try:
            mqtt_setup_tls(self._client)
            self._client.connect(self.broker, MQTT_PORT, keepalive=MQTT_KEEPALIVE)
            self._client.loop_start()
            ok = self._connected_event.wait(timeout=timeout)
            if ok and self.connected:
                return True
            self._client.loop_stop()
        except Exception as exc:
            log.warning("MQTT %s error: %s", self.broker, exc)
            try:
                self._client.loop_stop()
            except Exception:
                pass
        return False

    def publish(self, info: dict) -> None:
        if not self.connected:
            return
        try:
            plaintext = json.dumps(info).encode("utf-8")
            encrypted = signaling_encrypt(self._sig_key, plaintext)
            self._client.publish(self._topic_pub, encrypted, qos=1, retain=True)
        except Exception as exc:
            log.warning("MQTT publish failed on %s: %s", self.broker, exc)

    def clear_retained(self) -> None:
        if not self.connected:
            return
        try:
            self._client.publish(self._topic_pub, b"", qos=1, retain=True)
        except Exception:
            pass

    def disconnect(self) -> None:
        try:
            self._client.loop_stop()
            self._client.disconnect()
        except Exception:
            pass

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            self.connected = True
            client.subscribe(self._topic_sub, qos=1)
            log.info("MQTT connected to %s", self.broker)
        else:
            log.warning("MQTT %s refused: %s", self.broker, reason_code)
        self._connected_event.set()

    def _on_message(self, client, userdata, msg):
        if not msg.payload:
            return
        try:
            decrypted = signaling_decrypt(self._sig_key, msg.payload)
            payload   = json.loads(decrypted.decode("utf-8"))
            self._on_peer_cb(payload)
        except Exception as exc:
            log.debug("MQTT bad message on %s: %s", self.broker, exc)

    def _on_disconnect(self, client, userdata, flags, reason_code, properties=None):
        self.connected = False


# ════════════════════════════════════════════════════════════════════
#  ntfy.sh HTTP connection  (HTTPS port 443 — bypasses MQTT blocks)
# ════════════════════════════════════════════════════════════════════

class _NtfyConn:
    """
    Signaling via ntfy.sh over HTTPS.
    Works on any network that allows HTTPS (port 443).

    Topics are first 24 hex chars of the HMAC-derived topic_id, prefixed
    with "ss" to stay within ntfy's 64-char limit.
    Messages are base64-encoded encrypted blobs (≤ 4096 bytes → fine for signaling).
    """

    NTFY_BASE     = "https://ntfy.sh"
    POLL_INTERVAL = 0.5   # seconds between polls — fast enough to catch messages
    SINCE_INIT    = "15m"

    def __init__(self, topic_sub: str, topic_pub: str,
                 sig_key, on_peer_cb: Callable):
        self._topic_sub  = topic_sub
        self._topic_pub  = topic_pub
        self._sig_key    = sig_key
        self._on_peer_cb = on_peer_cb
        self.connected   = False
        self._stop       = threading.Event()
        self._ssl_ctx    = _make_ssl_ctx()
        self._poll_thread: Optional[threading.Thread] = None

    def connect(self, timeout: float = 10) -> bool:
        """Verify ntfy.sh is reachable, then start background poll thread."""
        try:
            req = urllib.request.Request(
                f"{self.NTFY_BASE}/{self._topic_sub}/json?poll=1&limit=0",
                headers={"User-Agent": "SecureShare/2.0"},
            )
            with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=timeout):
                pass
            self.connected = True
            self._poll_thread = threading.Thread(
                target=self._poll_loop, daemon=True, name="ntfy-poll"
            )
            self._poll_thread.start()
            log.info("ntfy.sh signaling ready (sub=%s)", self._topic_sub)
            return True
        except Exception as exc:
            log.warning("ntfy.sh unreachable: %s", exc)
            return False

    def publish(self, info: dict) -> None:
        if not self.connected:
            return
        try:
            plaintext = json.dumps(info).encode("utf-8")
            encrypted = signaling_encrypt(self._sig_key, plaintext)
            b64_body  = base64.b64encode(encrypted)
            req = urllib.request.Request(
                f"{self.NTFY_BASE}/{self._topic_pub}",
                data=b64_body,
                headers={
                    "User-Agent":    "SecureShare/2.0",
                    "Content-Type":  "text/plain",
                },
            )
            with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=10) as resp:
                log.info("ntfy.sh published (status %s)", resp.status)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                log.warning("ntfy.sh rate-limited (429) — will retry on next publish")
            else:
                log.warning("ntfy.sh publish HTTP %s: %s", exc.code, exc)
        except Exception as exc:
            log.warning("ntfy.sh publish failed: %s", exc)

    def clear_retained(self) -> None:
        pass  # ntfy messages expire automatically

    def disconnect(self) -> None:
        self._stop.set()
        self.connected = False

    # ── Internal ───────────────────────────────────────────────────

    def _poll_loop(self) -> None:
        since = self.SINCE_INIT
        seen_ids: set[str] = set()

        while not self._stop.is_set():
            try:
                url = (
                    f"{self.NTFY_BASE}/{self._topic_sub}"
                    f"/json?poll=1&since={since}"
                )
                req = urllib.request.Request(
                    url, headers={"User-Agent": "SecureShare/2.0"}
                )
                with urllib.request.urlopen(
                    req, context=self._ssl_ctx, timeout=10
                ) as resp:
                    for raw_line in resp:
                        raw_line = raw_line.strip()
                        if not raw_line:
                            continue
                        try:
                            event = json.loads(raw_line)
                        except Exception:
                            continue
                        if event.get("event") != "message":
                            continue
                        msg_id = event.get("id", "")
                        if msg_id in seen_ids:
                            continue
                        seen_ids.add(msg_id)
                        try:
                            raw_b64 = event.get("message", "")
                            encrypted = base64.b64decode(raw_b64)
                            decrypted = signaling_decrypt(self._sig_key, encrypted)
                            payload   = json.loads(decrypted.decode("utf-8"))
                            log.info("ntfy.sh received peer info")
                            self._on_peer_cb(payload)
                        except Exception as exc:
                            log.debug("ntfy.sh message parse error: %s", exc)
                # Keep looking back 15m so late-joining peer always finds us
                since = self.SINCE_INIT
            except Exception as exc:
                log.debug("ntfy.sh poll error: %s", exc)

            self._stop.wait(timeout=self.POLL_INTERVAL)


# ════════════════════════════════════════════════════════════════════
#  SignalingClient — MQTT + ntfy.sh in parallel
# ════════════════════════════════════════════════════════════════════

def _ntfy_topic(topic_id: str, suffix: str) -> str:
    """
    Build a valid ntfy.sh topic name from the HMAC-derived topic_id.
    Format: ss<24 hex chars><suffix>   (total ≤ 28 chars)
    """
    return f"ss{topic_id[:24]}{suffix}"


class SignalingClient:
    """
    Publish own connection info and wait for the peer's.

    Connects to ALL MQTT brokers + ntfy.sh simultaneously.
    Publishes on every channel that connects successfully.
    The two peers meet on whichever channel(s) they share.
    """

    def __init__(self, session_code: str, role: str):
        self.session_code = session_code
        self.role = role

        sig_key  = derive_signaling_key(session_code)
        topic_id = derive_topic_id(session_code)

        # MQTT topics
        mqtt_base = f"{MQTT_TOPIC_PREFIX}/{topic_id}"
        peer_role = "receiver" if role == "sender" else "sender"

        # ntfy topics (short, URL-safe)
        ntfy_sub = _ntfy_topic(topic_id, f"_{peer_role[0]}")  # _s or _r
        ntfy_pub = _ntfy_topic(topic_id, f"_{role[0]}")

        self._peer_info:  Optional[dict] = None
        self._peer_event  = threading.Event()
        self._peer_lock   = threading.Lock()

        # All channels
        self._mqtt_conns: list[_BrokerConn] = [
            _BrokerConn(
                broker,
                f"{mqtt_base}/{peer_role}",
                f"{mqtt_base}/{role}",
                sig_key, self._on_peer,
            )
            for broker in MQTT_BROKERS
        ]
        self._ntfy_conn = _NtfyConn(ntfy_sub, ntfy_pub, sig_key, self._on_peer)
        self._all_conns: list = [*self._mqtt_conns, self._ntfy_conn]

    # ── callbacks ──────────────────────────────────────────────────

    def _on_peer(self, payload: dict) -> None:
        with self._peer_lock:
            if self._peer_info is None:
                self._peer_info = payload
                self._peer_event.set()

    # ── public API ─────────────────────────────────────────────────

    def connect(self, timeout: float = 10) -> bool:
        """Connect to all channels in parallel; return True if ≥1 succeeds."""
        results = [False] * len(self._all_conns)

        def _try(i: int, conn) -> None:
            results[i] = conn.connect(timeout=timeout)

        threads = [
            threading.Thread(target=_try, args=(i, c), daemon=True)
            for i, c in enumerate(self._all_conns)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        mqtt_ok = sum(results[:len(self._mqtt_conns)])
        ntfy_ok = results[-1]
        log.info(
            "Signaling: %d/%d MQTT brokers + ntfy.sh=%s",
            mqtt_ok, len(self._mqtt_conns), "✓" if ntfy_ok else "✗",
        )
        return any(results)

    def publish_info(self, info: dict) -> None:
        """Publish encrypted info on every connected channel."""
        self._last_info = {**info, "role": self.role}
        for conn in self._all_conns:
            conn.publish(self._last_info)

    def wait_for_peer(self, timeout: float = 60) -> Optional[dict]:
        """
        Block until peer info arrives from any channel (or timeout).
        Re-publishes every 20 s so a late-joining peer can find us.
        """
        REPUBLISH_INTERVAL = 20
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            wait = min(REPUBLISH_INTERVAL, remaining)
            if self._peer_event.wait(timeout=wait):
                return self._peer_info
            # Re-publish in case the other side missed the first message
            if hasattr(self, "_last_info") and time.time() < deadline:
                for conn in self._all_conns:
                    conn.publish(self._last_info)
        return None

    def disconnect(self) -> None:
        for conn in self._all_conns:
            conn.clear_retained()
            conn.disconnect()

    @property
    def error(self) -> Optional[str]:
        if any(
            (getattr(c, "connected", False))
            for c in self._all_conns
        ):
            return None
        return "All signaling channels unavailable (MQTT + ntfy.sh)"
