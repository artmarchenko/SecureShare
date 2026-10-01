"""
SecureShare — encryption utilities (protocol v2).

X25519 key exchange + AES-256-GCM for end-to-end encryption.

What the relay learns / can do (threat model: compromised relay):
  - Room ID: the relay only sees `room_id`, derived from the session code with
    scrypt, so it never receives the code itself and brute-forcing the code
    offline is expensive.
  - Commit-then-reveal: the sender commits to its public key before it sees
    the receiver's. A relay substituting keys gets exactly one guess at a
    40-bit verification code instead of being able to grind for a match.
  - Transcript binding: the data key and the verification code are derived
    from both public keys in a fixed (sender, receiver) order.
  - Reconnect proof: a MAC under the *previous* session key over the *new*
    public keys; it cannot be replayed or forged by the relay.
  - AAD: every E2E frame is bound to the room, the frame type and (for data)
    the chunk number, so frames cannot be moved between sessions or reordered.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

LABEL = b"secureshare-p2"          # domain separation for protocol v2

ROLE_SENDER = "sender"
ROLE_RECEIVER = "receiver"
_ROLES = (ROLE_SENDER, ROLE_RECEIVER)

# scrypt cost for the session code: ~0.1 s / 32 MiB once per transfer on the
# client, which makes offline guessing of the code by the relay expensive.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1

SAS_BYTES = 5                       # 40-bit verification code -> 8 base32 chars


def _hkdf(key: bytes, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(key)


# ════════════════════════════════════════════════════════════════════
#  Secrets derived from the session code (known to both users only)
# ════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class SessionSecrets:
    room_id: str          # sent to the relay instead of the code
    signaling_key: bytes  # encrypts key-exchange / verification messages
    master: bytes         # salt for the E2E data key

    @classmethod
    def from_code(cls, session_code: str) -> "SessionSecrets":
        code = session_code.strip().lower().encode("utf-8")
        master = Scrypt(salt=LABEL + b"|code", length=32,
                        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(code)
        return cls(
            room_id=_hkdf(master, LABEL + b"|room", 16).hex(),
            signaling_key=_hkdf(master, LABEL + b"|signaling"),
            master=master,
        )


def new_session_code(length: int = 8) -> str:
    """Random session code like 'a7f3-bc21' (lowercase letters and digits)."""
    import secrets
    import string
    chars = string.ascii_lowercase + string.digits
    code = "".join(secrets.choice(chars) for _ in range(length))
    return f"{code[:4]}-{code[4:]}"


def signaling_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt a signaling payload: 12-byte random nonce ‖ ciphertext+tag.

    Random nonces are fine here: a session has only a handful of signaling
    messages.
    """
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, LABEL + b"|signaling")


def signaling_decrypt(key: bytes, data: bytes) -> bytes:
    """Decrypt a payload produced by signaling_encrypt()."""
    return AESGCM(key).decrypt(data[:12], data[12:], LABEL + b"|signaling")


# ════════════════════════════════════════════════════════════════════
#  Commit-then-reveal (sender commits to its key before seeing the peer's)
# ════════════════════════════════════════════════════════════════════

def make_commitment(public_key: bytes, opening: bytes | None = None) -> tuple[bytes, bytes]:
    """Return (commitment, opening_nonce) for `public_key`.

    `opening` is only passed by the test-vector generator; normally random.
    """
    opening = os.urandom(32) if opening is None else opening
    return hashlib.sha256(LABEL + b"|commit" + public_key + opening).digest(), opening


def check_commitment(commitment: bytes, public_key: bytes, opening: bytes) -> bool:
    expected = hashlib.sha256(LABEL + b"|commit" + public_key + opening).digest()
    return hmac.compare_digest(expected, commitment)


# ════════════════════════════════════════════════════════════════════
#  Session-level crypto (E2E after DH key exchange)
# ════════════════════════════════════════════════════════════════════

class CryptoSession:
    """
    One E2E-encrypted session between the sender and the receiver.

        cs = CryptoSession(secrets, ROLE_SENDER)
        pub = cs.get_public_key_bytes()          # (commit, then) send to peer
        cs.derive_shared_key(peer_pub_bytes)
        ct = cs.encrypt(plaintext, b"C")
        pt = cs.decrypt(ct, b"C")

    Nonce = 4-byte role prefix (sender 0, receiver 1) ‖ 8-byte counter, so
    the two directions never reuse a (key, nonce) pair.
    """

    NONCE_LEN = 12
    TAG_LEN = 16  # GCM tag is appended by AESGCM automatically

    def __init__(self, secrets: SessionSecrets, role: str, private_key: bytes | None = None):
        """`private_key` (raw 32 bytes) is only for deterministic test vectors."""
        if role not in _ROLES:
            raise ValueError(f"unknown role {role!r}")
        self.secrets = secrets
        self.role = role
        self._private_key = (X25519PrivateKey.generate() if private_key is None
                             else X25519PrivateKey.from_private_bytes(private_key))
        self._shared_key: bytes | None = None
        self._aes: AESGCM | None = None
        self._send_counter = 0
        self._nonce_prefix = _ROLES.index(role)
        self.transcript = b""            # sender_pub ‖ receiver_pub
        self._aad_base = LABEL + b"|" + secrets.room_id.encode("ascii") + b"|"

    # ── Key exchange ───────────────────────────────────────────────

    def get_public_key_bytes(self) -> bytes:
        """Return raw 32-byte public key to send to the peer."""
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )

    def derive_shared_key(self, peer_public_key_bytes: bytes) -> None:
        """Derive the AES-256 key, bound to both public keys and the code."""
        raw_secret = self._private_key.exchange(X25519PublicKey.from_public_bytes(peer_public_key_bytes))
        mine = self.get_public_key_bytes()
        self.transcript = mine + peer_public_key_bytes if self.role == ROLE_SENDER \
            else peer_public_key_bytes + mine
        self._shared_key = _hkdf(raw_secret, LABEL + b"|data-key|" + self.transcript,
                                 salt=self.secrets.master)
        self._aes = AESGCM(self._shared_key)

    def _require_key(self) -> bytes:
        if not self._shared_key:
            raise ValueError("Call derive_shared_key first")
        return self._shared_key

    def mac(self, data: bytes) -> bytes:
        """HMAC-SHA256 of `data` keyed with the session's shared key."""
        return hmac.new(self._require_key(), data, hashlib.sha256).digest()

    def get_verification_code(self) -> str:
        """8-character base32 code (40 bits) both users compare, e.g. 'K7PQ-2XMA'."""
        sas = _hkdf(self._require_key(), LABEL + b"|sas|" + self.transcript, SAS_BYTES)
        text = base64.b32encode(sas).decode("ascii")
        return f"{text[:4]}-{text[4:8]}"

    # ── Reconnect proof ────────────────────────────────────────────

    def reconnect_proof(self, previous: "CryptoSession") -> bytes:
        """Prove to the peer that we held `previous`'s key, bound to *this*
        session's public keys and our role (no replay, no reflection)."""
        return previous.mac(LABEL + b"|reconnect|" + self.role.encode() + b"|" + self.transcript)

    def check_reconnect_proof(self, previous: "CryptoSession", proof: bytes) -> bool:
        expected = previous.mac(LABEL + b"|reconnect|" + self.peer_role.encode() + b"|" + self.transcript)
        return hmac.compare_digest(expected, proof)

    # ── Encrypt / Decrypt ──────────────────────────────────────────

    @property
    def peer_role(self) -> str:
        return ROLE_RECEIVER if self.role == ROLE_SENDER else ROLE_SENDER

    def encrypt(self, plaintext: bytes, aad: bytes) -> bytes:
        """Returns 12-byte nonce ‖ ciphertext+tag.

        Bound as associated data: room id, the author's role (so the relay
        cannot reflect a frame back to its author) and `aad` (frame type,
        chunk number).
        """
        if not self._aes:
            raise ValueError("Call derive_shared_key first")
        nonce = struct.pack("!IQ", self._nonce_prefix, self._send_counter)
        self._send_counter += 1
        return nonce + self._aes.encrypt(nonce, plaintext, self._aad(self.role, aad))

    def decrypt(self, data: bytes, aad: bytes) -> bytes:
        """Decrypt a frame the *peer* produced with encrypt(..., aad)."""
        if not self._aes:
            raise ValueError("Call derive_shared_key first")
        return self._aes.decrypt(data[:self.NONCE_LEN], data[self.NONCE_LEN:], self._aad(self.peer_role, aad))

    def _aad(self, author: str, aad: bytes) -> bytes:
        return self._aad_base + author.encode("ascii") + b"|" + aad
