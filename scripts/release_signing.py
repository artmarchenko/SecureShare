#!/usr/bin/env python3
"""
Ed25519 signing of release checksums (SHA256SUMS.txt).

    # one-time: create a key pair (private key file must never be committed)
    python scripts/release_signing.py generate <private_key_out>
        -> prints the public key to embed in app/updater.py TRUSTED_RELEASE_KEYS

    # CI: sign; the private key comes from the RELEASE_SIGNING_KEY env var
    python scripts/release_signing.py sign dist/SHA256SUMS.txt
        -> writes dist/SHA256SUMS.txt.sig (base64 signature)

    # anyone: verify a downloaded release
    python scripts/release_signing.py verify SHA256SUMS.txt SHA256SUMS.txt.sig

Private key format: base64 of the 32-byte raw Ed25519 private key.
"""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]


def _raw_public(private: Ed25519PrivateKey) -> str:
    return base64.b64encode(private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def generate(out: Path) -> int:
    if out.exists():
        print(f"refusing to overwrite {out}", file=sys.stderr)
        return 1
    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(base64.b64encode(raw).decode() + "\n", encoding="ascii")
    try:
        os.chmod(out, 0o600)
    except OSError:
        pass
    print(f"private key written to {out}")
    print(f"public key (embed in TRUSTED_RELEASE_KEYS): {_raw_public(private)}")
    return 0


def sign(sums: Path) -> int:
    key_b64 = os.environ.get("RELEASE_SIGNING_KEY", "").strip()
    if not key_b64:
        print("RELEASE_SIGNING_KEY is not set - refusing to publish an unsigned release", file=sys.stderr)
        return 1
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_b64))
    signature = private.sign(sums.read_bytes())
    sig_path = sums.with_name(sums.name + ".sig")
    sig_path.write_text(base64.b64encode(signature).decode() + "\n", encoding="ascii")
    print(f"signed {sums.name} with key {_raw_public(private)[:12]}... -> {sig_path.name}")
    return verify(sums, sig_path)          # self-check against the embedded keys


def verify(sums: Path, sig: Path) -> int:
    sys.path.insert(0, str(ROOT))
    from app.updater import verify_checksums_signature
    ok = verify_checksums_signature(sums.read_bytes(), sig.read_text(encoding="ascii"))
    print("signature OK (trusted key)" if ok else "signature INVALID or key not trusted")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "generate":
        return generate(Path(argv[1]))
    if len(argv) == 2 and argv[0] == "sign":
        return sign(Path(argv[1]))
    if len(argv) == 3 and argv[0] == "verify":
        return verify(Path(argv[1]), Path(argv[2]))
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
