#!/usr/bin/env python3
"""
Deterministic test vectors for SecureShare protocol v2.

Other implementations (the Android app in mobile/) must reproduce every value
byte for byte. The Python test suite checks that the committed file still
matches what app/ computes, so the vectors cannot drift from the real code.

    python scripts/protocol_vectors.py            # (re)write tests/vectors/protocol_v2.json
    python scripts/protocol_vectors.py --check    # exit 1 if the file is out of date
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.config import PROTOCOL_VERSION, VPS_CHUNK_SIZE  # noqa: E402
from app.crypto_utils import (  # noqa: E402
    LABEL,
    ROLE_RECEIVER,
    ROLE_SENDER,
    SAS_BYTES,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
    CryptoSession,
    SessionSecrets,
    make_commitment,
    signaling_decrypt,
)
from app.ws_relay import (  # noqa: E402
    _CTL,
    _DAT,
    _SIG,
    _compress,
    _make_transfer_id,
    _safe_file_name,
)

OUT = ROOT / "tests" / "vectors" / "protocol_v2.json"


def _seed(label: str) -> bytes:
    """Fixed 32-byte value derived from a label (stands in for randomness)."""
    return hashlib.sha256(b"secureshare-test-vector|" + label.encode()).digest()


def _pair(secrets: SessionSecrets, tag: str) -> tuple[CryptoSession, CryptoSession, bytes, bytes]:
    s_priv, r_priv = _seed(f"{tag}|sender"), _seed(f"{tag}|receiver")
    s = CryptoSession(secrets, ROLE_SENDER, private_key=s_priv)
    r = CryptoSession(secrets, ROLE_RECEIVER, private_key=r_priv)
    s.derive_shared_key(r.get_public_key_bytes())
    r.derive_shared_key(s.get_public_key_bytes())
    return s, r, s_priv, r_priv


# Signaling encryption uses a random nonce, so this ciphertext was produced
# once by signaling_encrypt() and is frozen here: other implementations must
# be able to decrypt it (and their own output must decrypt in Python).
_SIGNALING_CODE = "ab12-cd34"
_SIGNALING_PLAINTEXT = b'{"type": "verified"}'


def build() -> dict:
    code = "ab12-cd34"
    secrets = SessionSecrets.from_code(code)

    session_secrets = []
    for raw in ("ab12-cd34", "  AB12-CD34 ", "k7pq-2xma", "0000-0000", "zz99-yy88"):
        sec = SessionSecrets.from_code(raw)
        session_secrets.append({
            "code": raw,
            "master": sec.master.hex(),
            "room_id": sec.room_id,
            "signaling_key": sec.signaling_key.hex(),
            # what the relay uses as the room key (server side, unchanged):
            "relay_room_key": hashlib.sha256(sec.room_id.encode()).hexdigest()[:32],
        })

    s, r, s_priv, r_priv = _pair(secrets, "session")
    opening = _seed("session|opening")
    commitment, _ = make_commitment(s.get_public_key_bytes(), opening)

    prev_s, prev_r, prev_s_priv, prev_r_priv = _pair(secrets, "previous")

    handshake = {
        "code": code,
        "sender_private": s_priv.hex(),
        "receiver_private": r_priv.hex(),
        "sender_public": s.get_public_key_bytes().hex(),
        "receiver_public": r.get_public_key_bytes().hex(),
        "transcript": s.transcript.hex(),
        "data_key": s._shared_key.hex(),
        "verification_code": s.get_verification_code(),
        "commitment": {"opening": opening.hex(), "value": commitment.hex()},
        "mac_example": {"data": b"hello".hex(), "mac": s.mac(b"hello").hex()},
        "reconnect": {
            "previous_sender_private": prev_s_priv.hex(),
            "previous_receiver_private": prev_r_priv.hex(),
            "previous_data_key": prev_s._shared_key.hex(),
            "proof_by_sender": s.reconnect_proof(prev_s).hex(),
            "proof_by_receiver": r.reconnect_proof(prev_r).hex(),
        },
    }

    # E2E frames, in the order each side encrypts them (counter starts at 0)
    meta = json.dumps({"type": "relay_meta", "name": "photo.jpg", "size": 600000,
                       "sha256": "ab" * 32, "chunk_size": VPS_CHUNK_SIZE,
                       "total_chunks": 2, "transfer_id": "cd" * 16}).encode()
    ack = json.dumps({"type": "relay_meta_ack"}).encode()
    raw_chunk = b"".join(_seed(f"chunk|{i}") for i in range(32))   # 1 KiB pseudo-random → flag 0x00
    zero_chunk = b"\x00" * 4096                                      # compressible → flag 0x01
    frames = []

    def ctl(author: CryptoSession, plaintext: bytes, note: str):
        counter = author._send_counter
        body = author.encrypt(plaintext, b"C")
        frames.append({"note": note, "author": author.role, "counter": counter, "type": "C",
                       "plaintext": plaintext.hex(), "wire": (bytes([_CTL]) + body).hex()})

    def dat(author: CryptoSession, seq: int, chunk: bytes, note: str):
        counter = author._send_counter
        payload = _compress(chunk)
        seq_bytes = struct.pack("!I", seq)
        body = author.encrypt(payload, b"D" + seq_bytes)
        frames.append({"note": note, "author": author.role, "counter": counter, "type": "D", "seq": seq,
                       "chunk": chunk.hex(), "payload": payload.hex(),
                       "wire": (bytes([_DAT]) + seq_bytes + body).hex()})

    ctl(s, meta, "sender relay_meta")
    dat(s, 0, raw_chunk, "sender data chunk 0, sent raw (flag 0x00)")
    dat(s, 7, zero_chunk, "sender data chunk 7, zlib level 1 (flag 0x01)")
    ctl(r, ack, "receiver relay_meta_ack")

    sig_key = SessionSecrets.from_code(_SIGNALING_CODE).signaling_key
    sig_wire = bytes.fromhex(_PINNED_SIGNALING_WIRE)
    assert signaling_decrypt(sig_key, sig_wire[1:]) == _SIGNALING_PLAINTEXT

    return {
        "protocol_version": PROTOCOL_VERSION,
        "description": "SecureShare protocol v2 test vectors — generated by scripts/protocol_vectors.py; "
                       "see DEVELOPER.md sections 3-4.",
        "constants": {
            "label": LABEL.decode(),
            "scrypt": {"salt": (LABEL + b"|code").decode(), "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "length": 32},
            "hkdf_info": {
                "room_id": (LABEL + b"|room").decode() + "  (16 bytes, hex)",
                "signaling_key": (LABEL + b"|signaling").decode(),
                "data_key": (LABEL + b"|data-key|").decode() + " + transcript; salt = master",
                "sas": (LABEL + b"|sas|").decode() + " + transcript; key = data key; 5 bytes -> base32",
            },
            "signaling_aad": (LABEL + b"|signaling").decode(),
            "e2e_aad": (LABEL + b"|").decode() + "<room_id ascii>|<author role>|<C or D+seq(4, BE)>",
            "commitment": "SHA256(" + (LABEL + b"|commit").decode() + " + sender_public + opening)",
            "reconnect_proof": "HMAC-SHA256(previous data key, " + (LABEL + b"|reconnect|").decode()
                               + "<author role>|" + " + transcript)",
            "nonce": "4-byte BE role prefix (sender 0, receiver 1) + 8-byte BE counter",
            "sas_bytes": SAS_BYTES,
            "frame_types": {"signaling": _SIG, "control": _CTL, "data": _DAT},
            "chunk_size": VPS_CHUNK_SIZE,
            "compression": "flag 0x01 + zlib(level 1) if it saves more than 64 bytes, else flag 0x00 + raw",
        },
        "session_secrets": session_secrets,
        "handshake": handshake,
        "frames": frames,
        "signaling": {
            "code": _SIGNALING_CODE,
            "plaintext": _SIGNALING_PLAINTEXT.hex(),
            "wire": _PINNED_SIGNALING_WIRE,
        },
        "transfer_id": [
            {"name": n, "size": z, "sha256": h, "id": _make_transfer_id(n, z, h)}
            for n, z, h in (("photo.jpg", 600000, "ab" * 32), ("Звіт 2026.pdf", 1, "00" * 32))
        ],
        "zlib_compatibility_note": "Receivers must accept any valid zlib stream after flag 0x01; "
                                   "senders need not reproduce Python's exact compressed bytes.",
        "zlib_example": {"input": zero_chunk[:64].hex(), "compressed": zlib.compress(zero_chunk[:64], 1).hex()},
        "safe_file_names": [{"raw": raw, "expected": _safe_file_name(raw)} for raw in _NAME_CASES],
    }


_NAME_CASES = [
    "report.pdf", "../../evil.txt", "..\\..\\evil.txt", "C:\\Windows\\evil.txt", "/etc/passwd",
    "notes.txt:hidden", 'a<b>c|d?.txt', "tab\there.txt", "trailing. . ", "CON", "nul.txt", "Com1.log",
    "console.txt", "Українська назва.docx", "", ".", "..", "dir/", "a\x00b", ". . .", "x" * 300,
]

# Produced once with signaling_encrypt(key("ab12-cd34"), b'{"type": "verified"}'), prefixed with 0x53.
_PINNED_SIGNALING_WIRE = ("53d812a4e6ccb1fc44d8c2dbcc3b2938d6031afe276de146d3b4319c737bfe48"
                          "ff8e24f1f14c6a720937269609e0752163")


def main(argv: list[str]) -> int:
    text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in argv:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print(f"{OUT.relative_to(ROOT)} is out of date — run scripts/protocol_vectors.py")
            return 1
        print("vectors up to date")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
