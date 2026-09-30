import json
import os
import socket
import time

import pytest

from app import ws_relay
from app.ws_relay import (
    _compress,
    _decompress,
    _delete_manifest,
    _is_dns_error,
    _load_manifest,
    _make_reconnect_token,
    _make_transfer_id,
    _manifest_path,
    _save_manifest,
    _sha256_file,
)


# ── Compression framing ─────────────────────────────────────────────

@pytest.mark.parametrize("data", [
    b"",
    b"x",
    b"a" * 64,
    b"a" * 65,
    b"\x00" * (512 * 1024),
    os.urandom(4096),
], ids=["empty", "1byte", "64same", "65same", "512k-zeros", "4k-random"])
def test_compress_roundtrip(data):
    assert _decompress(_compress(data)) == data


def test_compressible_data_uses_compressed_flag():
    assert _compress(b"\x00" * 10_000)[0] == 0x01


def test_random_data_is_sent_raw():
    framed = _compress(os.urandom(10_000))
    assert framed[0] == 0x00
    assert len(framed) == 10_001


def test_small_saving_is_not_worth_compressing():
    # Saving must exceed 64 bytes, otherwise the raw form is used.
    assert _compress(b"ab" * 20)[0] == 0x00


# ── Identifiers ─────────────────────────────────────────────────────

def test_transfer_id_is_deterministic_and_input_sensitive():
    base = _make_transfer_id("a.zip", 100, "f" * 64)
    assert base == _make_transfer_id("a.zip", 100, "f" * 64)
    assert len(base) == 32
    assert base != _make_transfer_id("b.zip", 100, "f" * 64)
    assert base != _make_transfer_id("a.zip", 101, "f" * 64)
    assert base != _make_transfer_id("a.zip", 100, "e" * 64)


def test_reconnect_token_depends_on_key_and_code():
    t1 = _make_reconnect_token(b"k" * 32, "ab12-cd34")
    assert t1 == _make_reconnect_token(b"k" * 32, "ab12-cd34")
    assert t1 != _make_reconnect_token(b"j" * 32, "ab12-cd34")
    assert t1 != _make_reconnect_token(b"k" * 32, "zz99-yy88")


def test_sha256_file(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"abc")
    assert _sha256_file(p) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# ── DNS error detection ─────────────────────────────────────────────

def test_dns_error_detection():
    assert _is_dns_error(socket.gaierror(11001, "getaddrinfo failed"))
    assert _is_dns_error(OSError("[Errno -2] Name or service not known"))
    assert not _is_dns_error(ConnectionRefusedError("refused"))


# ── Resume manifest ─────────────────────────────────────────────────

def _save(tmp_path, name="big.iso", tid="t" * 32, chunks=frozenset({0, 1, 5})):
    _save_manifest(_manifest_path(tmp_path, name), tid, name, 3_000_000,
                   "s" * 64, 524288, 6, set(chunks))


def test_manifest_roundtrip(tmp_path):
    _save(tmp_path)
    m = _load_manifest(tmp_path, "big.iso", "t" * 32)
    assert m["received_chunks"] == {0, 1, 5}
    assert m["total_chunks"] == 6
    assert m["chunk_size"] == 524288


def test_manifest_path_naming(tmp_path):
    assert _manifest_path(tmp_path, "a.zip").name == "a.zip.part.resume"


def test_manifest_write_is_atomic_no_tmp_left(tmp_path):
    _save(tmp_path)
    assert [p.name for p in tmp_path.iterdir()] == ["big.iso.part.resume"]


def test_manifest_with_other_transfer_id_is_ignored_but_kept(tmp_path):
    _save(tmp_path)
    assert _load_manifest(tmp_path, "big.iso", "x" * 32) is None
    assert _manifest_path(tmp_path, "big.iso").exists()


def test_expired_manifest_is_deleted(tmp_path, monkeypatch):
    _save(tmp_path)
    future = time.time() + ws_relay.RESUME_MAX_AGE + 10
    monkeypatch.setattr(ws_relay.time, "time", lambda: future)
    assert _load_manifest(tmp_path, "big.iso", "t" * 32) is None
    assert not _manifest_path(tmp_path, "big.iso").exists()


def test_corrupt_manifest_is_deleted(tmp_path):
    _manifest_path(tmp_path, "big.iso").write_text("{not json", encoding="utf-8")
    assert _load_manifest(tmp_path, "big.iso", "t" * 32) is None
    assert not _manifest_path(tmp_path, "big.iso").exists()


def test_missing_manifest(tmp_path):
    assert _load_manifest(tmp_path, "nothing.bin", "t" * 32) is None


def test_delete_manifest_is_idempotent(tmp_path):
    _save(tmp_path)
    _delete_manifest(tmp_path, "big.iso")
    _delete_manifest(tmp_path, "big.iso")
    assert not _manifest_path(tmp_path, "big.iso").exists()


def test_manifest_json_is_sorted_list(tmp_path):
    _save(tmp_path, chunks={5, 0, 1})
    raw = json.loads(_manifest_path(tmp_path, "big.iso").read_text(encoding="utf-8"))
    assert raw["received_chunks"] == [0, 1, 5]


# ── File name safety (B6, B11) ──────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("report.pdf", "report.pdf"),
    ("../../evil.txt", "evil.txt"),
    ("..\\..\\evil.txt", "evil.txt"),
    ("C:\\Windows\\evil.txt", "evil.txt"),
    ("/etc/passwd", "passwd"),
    ("notes.txt:hidden", "notes.txt_hidden"),
    ("a<b>c|d?.txt", "a_b_c_d_.txt"),
    ("tab\there.txt", "tab_here.txt"),
    ("trailing. . ", "trailing"),
    ("CON", "_CON"),
    ("nul.txt", "_nul.txt"),
    ("Com1.log", "_Com1.log"),
    ("console.txt", "console.txt"),
    ("Українська назва.docx", "Українська назва.docx"),
    ("x" * 300, "x" * 255),
])
def test_safe_file_name(raw, expected):
    from app.ws_relay import _safe_file_name
    assert _safe_file_name(raw) == expected


@pytest.mark.parametrize("raw", ["", ".", "..", "dir/", "a\x00b", None, 42, ". . ."])
def test_safe_file_name_rejects(raw):
    from app.ws_relay import _safe_file_name
    assert _safe_file_name(raw) is None


def test_unique_path(tmp_path):
    from app.ws_relay import _unique_path
    target = tmp_path / "photo.jpg"
    assert _unique_path(target) == target
    target.write_bytes(b"1")
    assert _unique_path(target).name == "photo (1).jpg"
    (tmp_path / "photo (1).jpg").write_bytes(b"2")
    assert _unique_path(target).name == "photo (2).jpg"
    noext = tmp_path / "README"
    noext.write_bytes(b"x")
    assert _unique_path(noext).name == "README (1)"
