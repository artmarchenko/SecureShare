"""The committed protocol v2 vectors must match what app/ computes.

These vectors are the contract for other implementations (Android app).
Checks are semantic (not a text diff of the JSON) so they hold on every OS
and zlib version.
"""

from __future__ import annotations

import json
import zlib
from pathlib import Path

import pytest

from app.crypto_utils import (
    ROLE_RECEIVER,
    ROLE_SENDER,
    CryptoSession,
    SessionSecrets,
    make_commitment,
    signaling_decrypt,
)
from app.ws_relay import _decompress, _make_transfer_id, _safe_file_name

V = json.loads((Path(__file__).resolve().parents[1] / "vectors" / "protocol_v2.json").read_text(encoding="utf-8"))
H = V["handshake"]
B = bytes.fromhex


def _sessions(sender_priv_hex: str, receiver_priv_hex: str):
    secrets = SessionSecrets.from_code(H["code"])
    s = CryptoSession(secrets, ROLE_SENDER, private_key=B(sender_priv_hex))
    r = CryptoSession(secrets, ROLE_RECEIVER, private_key=B(receiver_priv_hex))
    s.derive_shared_key(r.get_public_key_bytes())
    r.derive_shared_key(s.get_public_key_bytes())
    return s, r


def test_protocol_version_matches_app():
    from app.config import PROTOCOL_VERSION
    assert V["protocol_version"] == PROTOCOL_VERSION


@pytest.mark.parametrize("case", V["session_secrets"], ids=lambda c: repr(c["code"]))
def test_session_secrets(case):
    import hashlib
    sec = SessionSecrets.from_code(case["code"])
    assert sec.master.hex() == case["master"]
    assert sec.room_id == case["room_id"]
    assert sec.signaling_key.hex() == case["signaling_key"]
    assert hashlib.sha256(sec.room_id.encode()).hexdigest()[:32] == case["relay_room_key"]


def test_handshake_values():
    s, r = _sessions(H["sender_private"], H["receiver_private"])
    assert s.get_public_key_bytes().hex() == H["sender_public"]
    assert r.get_public_key_bytes().hex() == H["receiver_public"]
    assert s.transcript.hex() == r.transcript.hex() == H["transcript"]
    assert s._shared_key.hex() == r._shared_key.hex() == H["data_key"]
    assert s.get_verification_code() == r.get_verification_code() == H["verification_code"]
    commitment, _ = make_commitment(s.get_public_key_bytes(), B(H["commitment"]["opening"]))
    assert commitment.hex() == H["commitment"]["value"]
    assert s.mac(B(H["mac_example"]["data"])).hex() == H["mac_example"]["mac"]


def test_reconnect_proofs():
    rc = H["reconnect"]
    s, r = _sessions(H["sender_private"], H["receiver_private"])
    prev_s, prev_r = _sessions(rc["previous_sender_private"], rc["previous_receiver_private"])
    assert prev_s._shared_key.hex() == rc["previous_data_key"]
    assert s.reconnect_proof(prev_s).hex() == rc["proof_by_sender"]
    assert r.reconnect_proof(prev_r).hex() == rc["proof_by_receiver"]
    assert r.check_reconnect_proof(prev_r, B(rc["proof_by_sender"]))
    assert s.check_reconnect_proof(prev_s, B(rc["proof_by_receiver"]))


def test_frames_encrypt_and_decrypt_exactly():
    s, r = _sessions(H["sender_private"], H["receiver_private"])
    by_role = {ROLE_SENDER: (s, r), ROLE_RECEIVER: (r, s)}
    for frame in V["frames"]:
        author, reader = by_role[frame["author"]]
        assert author._send_counter == frame["counter"], frame["note"]
        wire = B(frame["wire"])
        if frame["type"] == "C":
            assert wire[0] == 0x43
            assert author.encrypt(B(frame["plaintext"]), b"C") == wire[1:], frame["note"]
            assert reader.decrypt(wire[1:], b"C") == B(frame["plaintext"])
        else:
            seq = frame["seq"].to_bytes(4, "big")
            assert wire[0] == 0x44 and wire[1:5] == seq
            payload = B(frame["payload"])
            assert author.encrypt(payload, b"D" + seq) == wire[5:], frame["note"]
            assert reader.decrypt(wire[5:], b"D" + seq) == payload
            assert _decompress(payload) == B(frame["chunk"])


def test_compression_flags():
    flags = {f["note"]: B(f["payload"])[0] for f in V["frames"] if f["type"] == "D"}
    assert sorted(flags.values()) == [0x00, 0x01]
    ex = V["zlib_example"]
    assert zlib.decompress(B(ex["compressed"])) == B(ex["input"])


def test_signaling_vector_decrypts():
    sig = V["signaling"]
    key = SessionSecrets.from_code(sig["code"]).signaling_key
    wire = B(sig["wire"])
    assert wire[0] == 0x53
    assert signaling_decrypt(key, wire[1:]) == B(sig["plaintext"])


@pytest.mark.parametrize("case", V["transfer_id"], ids=lambda c: c["name"])
def test_transfer_id(case):
    assert _make_transfer_id(case["name"], case["size"], case["sha256"]) == case["id"]


@pytest.mark.parametrize("case", V["safe_file_names"], ids=lambda c: repr(c["raw"])[:30])
def test_safe_file_names(case):
    assert _safe_file_name(case["raw"]) == case["expected"]
