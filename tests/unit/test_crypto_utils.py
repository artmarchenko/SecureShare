"""Protocol v2 cryptography: secrets from the code, commitments, keys, SAS, proofs, AAD."""

import re
import struct

import pytest
from cryptography.exceptions import InvalidTag

from app.crypto_utils import (
    ROLE_RECEIVER,
    ROLE_SENDER,
    CryptoSession,
    SessionSecrets,
    check_commitment,
    make_commitment,
    signaling_decrypt,
    signaling_encrypt,
)

CODE = "ab12-cd34"


@pytest.fixture(scope="module")
def secrets():
    return SessionSecrets.from_code(CODE)


@pytest.fixture(scope="module")
def other_secrets():
    return SessionSecrets.from_code("zz99-yy88")


def paired(secrets_s, secrets_r=None):
    s = CryptoSession(secrets_s, ROLE_SENDER)
    r = CryptoSession(secrets_r or secrets_s, ROLE_RECEIVER)
    s.derive_shared_key(r.get_public_key_bytes())
    r.derive_shared_key(s.get_public_key_bytes())
    return s, r


# ── Secrets derived from the session code ───────────────────────────

def test_secrets_are_deterministic_and_normalised(secrets):
    assert SessionSecrets.from_code("  AB12-CD34 ") == secrets


def test_room_id_does_not_reveal_the_code(secrets):
    assert re.fullmatch(r"[0-9a-f]{32}", secrets.room_id)
    assert CODE not in secrets.room_id and CODE.replace("-", "") not in secrets.room_id


def test_different_codes_give_unrelated_secrets(secrets, other_secrets):
    assert secrets.room_id != other_secrets.room_id
    assert secrets.signaling_key != other_secrets.signaling_key
    assert len({secrets.room_id, secrets.signaling_key.hex(), secrets.master.hex()}) == 3


# ── Commitment (S1) ─────────────────────────────────────────────────

def test_commitment_opens_only_for_the_committed_key():
    pub, other = b"\x01" * 32, b"\x02" * 32
    commit, opening = make_commitment(pub)
    assert check_commitment(commit, pub, opening)
    assert not check_commitment(commit, other, opening)          # key swapped after commit
    assert not check_commitment(commit, pub, b"\x00" * 32)       # wrong opening


def test_commitments_are_hiding():
    pub = b"\x01" * 32
    assert make_commitment(pub)[0] != make_commitment(pub)[0]    # random opening


# ── Key agreement and verification code ────────────────────────────

def test_both_sides_agree_on_key_and_code(secrets):
    s, r = paired(secrets)
    assert s._shared_key == r._shared_key
    assert s.transcript == r.transcript
    assert s.get_verification_code() == r.get_verification_code()


def test_verification_code_is_40_bit_base32(secrets):
    code = paired(secrets)[0].get_verification_code()
    assert re.fullmatch(r"[A-Z2-7]{4}-[A-Z2-7]{4}", code)


def test_code_depends_on_both_public_keys(secrets):
    # A relay that substitutes either key ends up with different codes on the
    # two sides (it would need to guess 40 bits in one shot — see commitment).
    s1, _ = paired(secrets)
    s2, _ = paired(secrets)
    assert s1.get_verification_code() != s2.get_verification_code()


def test_session_code_is_bound_into_the_data_key(secrets, other_secrets):
    s, r = paired(secrets, other_secrets)
    assert s._shared_key != r._shared_key


def test_role_is_validated(secrets):
    with pytest.raises(ValueError):
        CryptoSession(secrets, "observer")


def test_crypto_requires_key_exchange(secrets):
    cs = CryptoSession(secrets, ROLE_SENDER)
    for call in (lambda: cs.encrypt(b"x", b"C"), lambda: cs.mac(b"x"), cs.get_verification_code):
        with pytest.raises(ValueError):
            call()


# ── Encryption with AAD (S4 + reflection) ───────────────────────────

@pytest.mark.parametrize("size", [0, 1, 4096, 512 * 1024])
def test_roundtrip_both_directions(secrets, size):
    s, r = paired(secrets)
    data = bytes(size)
    assert r.decrypt(s.encrypt(data, b"C"), b"C") == data
    assert s.decrypt(r.encrypt(data, b"C"), b"C") == data


def test_nonces_never_repeat_across_both_directions(secrets):
    s, r = paired(secrets)
    nonces = [s.encrypt(b"", b"C")[:12] for _ in range(3000)] + [r.encrypt(b"", b"C")[:12] for _ in range(3000)]
    assert len(set(nonces)) == len(nonces)


def test_chunk_number_is_authenticated(secrets):
    s, r = paired(secrets)
    frame = s.encrypt(b"chunk seven", b"D" + struct.pack("!I", 7))
    assert r.decrypt(frame, b"D" + struct.pack("!I", 7)) == b"chunk seven"
    with pytest.raises(InvalidTag):                               # relabelled as chunk 8
        r.decrypt(frame, b"D" + struct.pack("!I", 8))


def test_frame_type_is_authenticated(secrets):
    s, r = paired(secrets)
    with pytest.raises(InvalidTag):
        r.decrypt(s.encrypt(b"{}", b"C"), b"D" + bytes(4))


def test_reflected_frame_is_rejected(secrets):
    s, _ = paired(secrets)
    with pytest.raises(InvalidTag):                               # relay echoes the sender's own frame
        s.decrypt(s.encrypt(b'{"type":"relay_done_ack","verified":true}', b"C"), b"C")


def test_frame_from_other_session_is_rejected(secrets, other_secrets):
    s, _ = paired(secrets)
    _, r_other = paired(other_secrets)
    with pytest.raises(InvalidTag):
        r_other.decrypt(s.encrypt(b"x", b"C"), b"C")


def test_tampered_ciphertext_is_rejected(secrets):
    s, r = paired(secrets)
    ct = bytearray(s.encrypt(b"secret", b"C"))
    ct[-1] ^= 1
    with pytest.raises(InvalidTag):
        r.decrypt(bytes(ct), b"C")


# ── Reconnect proof (S2) ────────────────────────────────────────────

def test_reconnect_proof_accepted_from_the_real_peer(secrets):
    old_s, old_r = paired(secrets)
    new_s, new_r = paired(secrets)
    assert new_r.check_reconnect_proof(old_r, new_s.reconnect_proof(old_s))
    assert new_s.check_reconnect_proof(old_s, new_r.reconnect_proof(old_r))


def test_reconnect_proof_cannot_be_replayed_into_another_session(secrets):
    # A proof observed in one reconnect is useless in a key exchange with
    # different public keys (e.g. one where keys were substituted).
    old_s, old_r = paired(secrets)
    new_s, _ = paired(secrets)
    captured = new_s.reconnect_proof(old_s)
    _, other_r = paired(secrets)
    assert not other_r.check_reconnect_proof(old_r, captured)


def test_reconnect_proof_cannot_be_reflected(secrets):
    old_s, old_r = paired(secrets)
    _, new_r = paired(secrets)
    assert not new_r.check_reconnect_proof(old_r, new_r.reconnect_proof(old_r))


def test_reconnect_proof_requires_the_previous_key(secrets):
    old_s, old_r = paired(secrets)
    unrelated_s, _ = paired(secrets)
    new_s, new_r = paired(secrets)
    assert not new_r.check_reconnect_proof(old_r, new_s.reconnect_proof(unrelated_s))


# ── Signaling layer ─────────────────────────────────────────────────

def test_signaling_roundtrip_and_random_nonce(secrets):
    c1 = signaling_encrypt(secrets.signaling_key, b"hello")
    c2 = signaling_encrypt(secrets.signaling_key, b"hello")
    assert c1 != c2
    assert signaling_decrypt(secrets.signaling_key, c1) == b"hello"


def test_signaling_wrong_code_is_rejected(secrets, other_secrets):
    with pytest.raises(InvalidTag):
        signaling_decrypt(other_secrets.signaling_key, signaling_encrypt(secrets.signaling_key, b"x"))


def test_mac_is_shared(secrets):
    s, r = paired(secrets)
    assert s.mac(b"x") == r.mac(b"x") and s.mac(b"x") != s.mac(b"y")
