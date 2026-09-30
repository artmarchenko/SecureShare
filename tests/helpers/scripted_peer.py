"""A protocol-level peer whose messages the test controls.

It performs the normal key exchange and verification of protocol v1, then
lets the test send arbitrary (possibly invalid) control/data frames to the
real VPSRelayReceiver. Used to check that the receiver validates what the
other side sends.
"""

from __future__ import annotations

import base64
import json
import struct

import websocket

from app.config import APP_VERSION, PROTOCOL_VERSION
from app.crypto_utils import CryptoSession, derive_signaling_key, signaling_decrypt, signaling_encrypt
from app.ws_relay import _compress

SIG, CTL, DAT = 0x53, 0x43, 0x44


class ScriptedPeer:
    def __init__(self, url: str, code: str, protocol_version: int = PROTOCOL_VERSION):
        self.code = code
        self.sig_key = derive_signaling_key(code)
        self.crypto = CryptoSession(code)
        self.ws = websocket.create_connection(url, timeout=20)
        self.ws.send(code)
        self.protocol_version = protocol_version

    def handshake(self) -> None:
        hello = {
            "type": "pub_key",
            "key": base64.b64encode(self.crypto.get_public_key_bytes()).decode(),
            "protocol_version": self.protocol_version,
            "app_version": APP_VERSION,
        }
        self._send_sig(hello)
        peer = self._recv_sig()
        self.crypto.derive_shared_key(base64.b64decode(peer["key"]))

    def verify(self) -> None:
        self._send_sig({"type": "verified"})
        assert self._recv_sig()["type"] == "verified"

    def send_ctl(self, msg: dict) -> None:
        self.ws.send_binary(bytes([CTL]) + self.crypto.encrypt(json.dumps(msg).encode()))

    def send_chunk(self, seq: int, data: bytes) -> None:
        self.ws.send_binary(bytes([DAT]) + struct.pack("!I", seq) + self.crypto.encrypt(_compress(data)))

    def recv_ctl(self) -> dict:
        while True:
            raw = self.ws.recv()
            if isinstance(raw, bytes) and raw and raw[0] == CTL:
                return json.loads(self.crypto.decrypt(raw[1:]))

    def close(self) -> None:
        try:
            self.ws.close()
        except Exception:
            pass

    def _send_sig(self, msg: dict) -> None:
        self.ws.send_binary(bytes([SIG]) + signaling_encrypt(self.sig_key, json.dumps(msg).encode()))

    def _recv_sig(self) -> dict:
        raw = self.ws.recv()
        return json.loads(signaling_decrypt(self.sig_key, raw[1:]))
