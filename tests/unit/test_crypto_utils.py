import re

import pytest
from cryptography.exceptions import InvalidTag

from app.crypto_utils import (
    CryptoSession,
    derive_signaling_key,
    signaling_decrypt,
    signaling_encrypt,
)

CODE = "ab12-cd34"


def paired(code_a: str = CODE, code_b: str = CODE) -> tuple[CryptoSession, CryptoSession]:
    a, b = CryptoSession(code_a), CryptoSession(code_b)
    a.derive_shared_key(b.get_public_key_bytes())
    b.derive_shared_key(a.get_public_key_bytes())
    return a, b


# ── Key exchange ────────────────────────────────────────────────────

def test_public_key_is_32_raw_bytes():
    assert len(CryptoSession(CODE).get_public_key_bytes()) == 32


def test_each_session_has_fresh_keys():
    assert CryptoSession(CODE).get_public_key_bytes() != CryptoSession(CODE).get_public_key_bytes()


def test_both_sides_derive_same_key_and_verification_code():
    a, b = paired()
    assert a._shared_key == b._shared_key
    assert a.get_verification_code() == b.get_verification_code()


def test_verification_code_format():
    a, _ = paired()
    assert re.fullmatch(r"[0-9A-F]{4}-[0-9A-F]{4}", a.get_verification_code())


def test_verification_code_requires_key_exchange():
    with pytest.raises(ValueError):
        CryptoSession(CODE).get_verification_code()


def test_different_session_codes_give_different_keys():
    a, b = paired(CODE, "zz99-yy88")
    assert a._shared_key != b._shared_key


def test_nonce_prefixes_differ_between_peers():
    a, b = paired()
    assert {a._nonce_prefix, b._nonce_prefix} == {0, 1}


# ── Encrypt / decrypt ───────────────────────────────────────────────

@pytest.mark.parametrize("size", [0, 1, 16, 4096, 512 * 1024])
def test_roundtrip_both_directions(size):
    a, b = paired()
    data = bytes(range(256)) * (size // 256) + bytes(size % 256)
    assert b.decrypt(a.encrypt(data)) == data
    assert a.decrypt(b.encrypt(data)) == data


def test_ciphertext_overhead_is_nonce_plus_tag():
    a, _ = paired()
    assert len(a.encrypt(b"x" * 100)) == 100 + CryptoSession.NONCE_LEN + CryptoSession.TAG_LEN


def test_nonces_never_repeat_across_both_peers():
    a, b = paired()
    nonces = [a.encrypt(b"")[:12] for _ in range(5000)] + [b.encrypt(b"")[:12] for _ in range(5000)]
    assert len(set(nonces)) == len(nonces)


def test_tampered_ciphertext_is_rejected():
    a, b = paired()
    ct = bytearray(a.encrypt(b"secret data"))
    ct[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        b.decrypt(bytes(ct))


def test_ciphertext_from_other_session_is_rejected():
    a, _ = paired(CODE, CODE)
    _, other = paired("zz99-yy88", "zz99-yy88")
    with pytest.raises(InvalidTag):
        other.decrypt(a.encrypt(b"payload"))


def test_encrypt_before_key_exchange_fails():
    with pytest.raises(ValueError):
        CryptoSession(CODE).encrypt(b"x")


# ── Signaling layer ─────────────────────────────────────────────────

def test_signaling_key_is_deterministic_per_code():
    assert derive_signaling_key(CODE) == derive_signaling_key(CODE)
    assert derive_signaling_key(CODE) != derive_signaling_key("zz99-yy88")


def test_signaling_roundtrip_and_random_nonce():
    key = derive_signaling_key(CODE)
    c1, c2 = signaling_encrypt(key, b"hello"), signaling_encrypt(key, b"hello")
    assert c1 != c2
    assert signaling_decrypt(key, c1) == b"hello"


def test_signaling_wrong_code_is_rejected():
    ct = signaling_encrypt(derive_signaling_key(CODE), b"hello")
    with pytest.raises(InvalidTag):
        signaling_decrypt(derive_signaling_key("zz99-yy88"), ct)
