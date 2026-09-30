"""A protocol-level *sender* whose messages the test controls.

It performs the normal protocol v2 handshake (commit → receiver key →
reveal → session proof → verification) and then lets the test send
arbitrary, possibly invalid, control/data frames to the real
VPSRelayReceiver — to check that the receiver validates what it gets.
"""

from __future__ import annotations

import base64
import json
import struct

import websocket

from app.config import APP_VERSION, PROTOCOL_VERSION
from app.crypto_utils import (
    ROLE_SENDER,
    CryptoSession,
    SessionSecrets,
    make_commitment,
    signaling_decrypt,
    signaling_encrypt,
)
from app.ws_relay import _compress

SIG, CTL, DAT = 0x53, 0x43, 0x44


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


class ScriptedPeer:
    def __init__(self, url: str, code: str, protocol_version: int = PROTOCOL_VERSION):
        self.code = code
        self.secrets = SessionSecrets.from_code(code)
        self.sig_key = self.secrets.signaling_key
        self.crypto = CryptoSession(self.secrets, ROLE_SENDER)
        self.protocol_version = protocol_version
        self.ws = websocket.create_connection(url, timeout=20)
        self.ws.send(self.secrets.room_id)

    def handshake(self, reveal_key: bytes | None = None) -> None:
        """Commit → get the receiver's key → reveal → exchange session proofs.

        `reveal_key` lets a test reveal a different key than the committed one.
        """
        mine = self.crypto.get_public_key_bytes()
        commitment, opening = make_commitment(mine)
        self.send_sig({"type": "commit", "commit": _b64(commitment),
                       "protocol_version": self.protocol_version, "app_version": APP_VERSION})
        peer = self.recv_sig()
        assert peer["type"] == "pub_key", peer
        self.send_sig({"type": "reveal", "key": _b64(reveal_key or mine), "opening": _b64(opening)})
        if reveal_key is not None:
            return
        self.crypto.derive_shared_key(base64.b64decode(peer["key"]))
        self.send_sig({"type": "session_proof", "mac": None})
        assert self.recv_sig()["type"] == "session_proof"

    def verify(self) -> None:
        self.send_sig({"type": "verified"})
        assert self.recv_sig()["type"] == "verified"

    def send_ctl(self, msg: dict) -> None:
        self.ws.send_binary(bytes([CTL]) + self.crypto.encrypt(json.dumps(msg).encode(), b"C"))

    def send_chunk(self, seq: int, data: bytes, claimed_seq: int | None = None) -> None:
        """Send chunk `seq`; `claimed_seq` puts a different number in the frame header."""
        aad = b"D" + struct.pack("!I", seq)
        header = struct.pack("!I", seq if claimed_seq is None else claimed_seq)
        self.ws.send_binary(bytes([DAT]) + header + self.crypto.encrypt(_compress(data), aad))

    def recv_ctl(self) -> dict:
        while True:
            raw = self.ws.recv()
            if isinstance(raw, bytes) and raw and raw[0] == CTL:
                return json.loads(self.crypto.decrypt(raw[1:], b"C"))

    def close(self) -> None:
        try:
            self.ws.close()
        except Exception:
            pass

    def send_sig(self, msg: dict) -> None:
        self.ws.send_binary(bytes([SIG]) + signaling_encrypt(self.sig_key, json.dumps(msg).encode()))

    def recv_sig(self) -> dict:
        raw = self.ws.recv()
        return json.loads(signaling_decrypt(self.sig_key, raw[1:]))

    # kept for older tests
    _send_sig = send_sig
    _recv_sig = recv_sig
