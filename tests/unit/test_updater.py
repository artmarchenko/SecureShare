import hashlib
import io
import os
import struct
import tarfile
import zipfile

import pytest

from app import updater
from app.updater import (
    ReleaseInfo,
    _extract_tar,
    _extract_zip,
    _fetch_checksums,
    _is_temp_or_archive_path,
    _parse_version,
    _verify_binary,
    download_and_verify,
    is_newer,
)
from tests.helpers.http_files import FileServer


# ── Fake binaries ───────────────────────────────────────────────────

def fake_pe(size: int = 1_100_000) -> bytes:
    head = bytearray(b"MZ" + b"\x00" * 0x3A)
    head += struct.pack("<I", 0x80)
    head += b"\x00" * (0x80 - len(head))
    head += b"PE\x00\x00"
    return bytes(head) + b"\x90" * (size - len(head))


def fake_elf(size: int = 1_100_000) -> bytes:
    return b"\x7fELF" + b"\x00" * (size - 4)


def make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_tar(entries: dict[str, bytes], symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        if symlink:
            info = tarfile.TarInfo(symlink)
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tf.addfile(info)
    return buf.getvalue()


# ── Version parsing ─────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("3.4.0", (3, 4, 0)),
    ("v3.4.0", (3, 4, 0)),
    ("V10.0.1", (10, 0, 1)),
    ("3.4.0-rc1", (3, 4, 0)),
    ("3.x", (3, 0)),
])
def test_parse_version(raw, expected):
    assert _parse_version(raw) == expected


@pytest.mark.parametrize("remote,local,newer", [
    ("3.4.1", "3.4.0", True),
    ("3.10.0", "3.9.9", True),
    ("v4.0.0", "3.4.0", True),
    ("3.4.0", "3.4.0", False),
    ("3.3.1", "3.4.0", False),  # downgrade is never "newer"
])
def test_is_newer(remote, local, newer):
    assert is_newer(remote, local) is newer


# ── Settings persistence ────────────────────────────────────────────

def test_skip_and_clear_version():
    updater.skip_version("9.9.9")
    assert updater.is_version_skipped("9.9.9")
    assert not updater.is_version_skipped("9.9.8")
    updater.clear_skipped()
    assert not updater.is_version_skipped("9.9.9")


def test_check_cooldown(monkeypatch):
    updater.mark_checked()
    assert not updater.should_check_now()
    monkeypatch.setattr(updater.time, "time", lambda: 10 ** 12)
    assert updater.should_check_now()


# ── Binary checks ───────────────────────────────────────────────────

@pytest.mark.parametrize("system,blob,ok", [
    ("Windows", fake_pe(), True),
    ("Windows", fake_elf(), False),
    ("Linux", fake_elf(), True),
    ("Linux", fake_pe(), False),
    ("Windows", fake_pe(500_000), False),       # too small
], ids=["pe-win", "elf-on-win", "elf-linux", "pe-on-linux", "too-small"])
def test_verify_binary(tmp_path, monkeypatch, system, blob, ok):
    monkeypatch.setattr(updater.platform, "system", lambda: system)
    p = tmp_path / "bin"
    p.write_bytes(blob)
    assert _verify_binary(p)[0] is ok


def test_verify_binary_rejects_huge_file(tmp_path):
    p = tmp_path / "huge.exe"
    with open(p, "wb") as f:
        f.truncate(updater.MAX_BINARY_SIZE + 1)
    ok, err = _verify_binary(p)
    assert not ok and "too large" in err


def test_temp_or_archive_detection(monkeypatch):
    monkeypatch.setenv("TEMP", r"C:\Users\u\AppData\Local\Temp")
    monkeypatch.setenv("TMP", r"C:\Users\u\AppData\Local\Temp")
    assert _is_temp_or_archive_path(updater.Path(r"C:\Users\u\AppData\Local\Temp\Temp1_x.zip\SecureShare.exe"))
    assert _is_temp_or_archive_path(updater.Path(r"D:\dl\SecureShare.zip\SecureShare.exe"))
    assert not _is_temp_or_archive_path(updater.Path(r"C:\Tools\SecureShare\SecureShare.exe"))


# ── Archive extraction (malicious inputs) ───────────────────────────

def test_zip_ok(tmp_path):
    arc = tmp_path / "a.zip"
    arc.write_bytes(make_zip({"SecureShare.exe": b"MZ"}))
    out, err = _extract_zip(arc, tmp_path / "x")
    assert err == "" and out.read_bytes() == b"MZ"


@pytest.mark.parametrize("entries,needle", [
    ({"../evil.exe": b"x"}, "traversal"),
    ({"a/../../evil.exe": b"x"}, "traversal"),
    ({"/abs.exe": b"x"}, "Absolute"),
    ({"a.exe": b"x", "b.exe": b"y"}, "Multiple"),
    ({"readme.txt": b"x"}, "No .exe"),
], ids=["dotdot", "nested-dotdot", "absolute", "two-exe", "no-exe"])
def test_zip_rejects(tmp_path, entries, needle):
    arc = tmp_path / "a.zip"
    arc.write_bytes(make_zip(entries))
    out, err = _extract_zip(arc, tmp_path / "x")
    assert out is None and needle in err


def test_zip_corrupt(tmp_path):
    arc = tmp_path / "a.zip"
    arc.write_bytes(b"not a zip")
    assert _extract_zip(arc, tmp_path / "x") == (None, "Corrupted zip archive")


def test_tar_ok_sets_executable(tmp_path):
    arc = tmp_path / "a.tar.gz"
    arc.write_bytes(make_tar({"SecureShare": b"\x7fELF"}))
    out, err = _extract_tar(arc, tmp_path / "x")
    assert err == "" and out.read_bytes() == b"\x7fELF"


@pytest.mark.parametrize("entries,symlink,needle", [
    ({"../evil": b"x"}, None, "traversal"),
    ({"/abs": b"x"}, None, "Absolute"),
    ({"SecureShare": b"x"}, "link", "Symlink"),
    ({"a": b"x", "b": b"y"}, None, "Multiple"),
    ({}, None, "No files"),
], ids=["dotdot", "absolute", "symlink", "two-files", "empty"])
def test_tar_rejects(tmp_path, entries, symlink, needle):
    arc = tmp_path / "a.tar.gz"
    arc.write_bytes(make_tar(entries, symlink))
    out, err = _extract_tar(arc, tmp_path / "x")
    assert out is None and needle in err


# ── Checksums file parsing ──────────────────────────────────────────

@pytest.fixture
def cdn():
    server = FileServer()
    yield server
    server.close()


def test_fetch_checksums_formats(cdn):
    cdn.files["/SUMS"] = (
        b"# SecureShare v9 checksums\n"
        b"AAAA  SecureShare-v9.zip\n"
        b"bbbb *SecureShare-v9.exe\n"
        b"cccc  dist/sub/SecureShare-v9-linux-x64.tar.gz\n"
        b"\n"
    )
    assert _fetch_checksums(cdn.url("/SUMS")) == {
        "SecureShare-v9.zip": "aaaa",
        "SecureShare-v9.exe": "bbbb",
        "SecureShare-v9-linux-x64.tar.gz": "cccc",
    }


def test_fetch_checksums_unreachable_returns_empty(cdn):
    assert _fetch_checksums(cdn.url("/missing")) == {}
    assert _fetch_checksums("") == {}


# ── download_and_verify end-to-end against a fake CDN ───────────────

def _release(cdn, archive: bytes, name: str, sums: bytes | None, size: int | None = None) -> ReleaseInfo:
    cdn.files[f"/{name}"] = archive
    checksums_url = ""
    if sums is not None:
        cdn.files["/SHA256SUMS.txt"] = sums
        checksums_url = cdn.url("/SHA256SUMS.txt")
    return ReleaseInfo(
        tag="v9.9.9", version="9.9.9", name="v9", body="", html_url="", published="",
        win_download=cdn.url(f"/{name}"), win_size=len(archive) if size is None else size,
        checksums_url=checksums_url,
    )


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(updater.platform, "system", lambda: "Windows")


def test_download_ok(cdn, windows):
    arc = make_zip({"SecureShare.exe": fake_pe()})
    sums = f"{hashlib.sha256(arc).hexdigest()}  SecureShare-v9.9.9.zip\n".encode()
    binary, err = download_and_verify(_release(cdn, arc, "SecureShare-v9.9.9.zip", sums))
    assert err == ""
    assert binary.read_bytes() == fake_pe()


def test_download_sha_mismatch_is_rejected(cdn, windows):
    arc = make_zip({"SecureShare.exe": fake_pe()})
    sums = f"{'0' * 64}  SecureShare-v9.9.9.zip\n".encode()
    binary, err = download_and_verify(_release(cdn, arc, "SecureShare-v9.9.9.zip", sums))
    assert binary is None and "SHA-256 mismatch" in err


def test_download_size_mismatch_is_rejected(cdn, windows):
    arc = make_zip({"SecureShare.exe": fake_pe()})
    binary, err = download_and_verify(_release(cdn, arc, "SecureShare-v9.9.9.zip", None, size=123))
    assert binary is None and "Size mismatch" in err


def test_download_with_non_executable_payload_is_rejected(cdn, windows):
    arc = make_zip({"SecureShare.exe": os.urandom(1_100_000)})
    sums = f"{hashlib.sha256(arc).hexdigest()}  SecureShare-v9.9.9.zip\n".encode()
    binary, err = download_and_verify(_release(cdn, arc, "SecureShare-v9.9.9.zip", sums))
    assert binary is None and "PE header" in err


@pytest.mark.xfail(strict=True, reason="S5: updater is fail-open when SHA256SUMS.txt is missing")
def test_download_without_checksums_is_rejected(cdn, windows):
    arc = make_zip({"SecureShare.exe": fake_pe()})
    binary, err = download_and_verify(_release(cdn, arc, "SecureShare-v9.9.9.zip", None))
    assert binary is None


@pytest.mark.xfail(strict=True, reason="S5: archive missing from SHA256SUMS.txt is still installed")
def test_download_not_listed_in_checksums_is_rejected(cdn, windows):
    arc = make_zip({"SecureShare.exe": fake_pe()})
    sums = b"abcd  SomethingElse.zip\n"
    binary, err = download_and_verify(_release(cdn, arc, "SecureShare-v9.9.9.zip", sums))
    assert binary is None


# ── fetch_latest_release asset selection ────────────────────────────

def test_fetch_latest_release_picks_versioned_assets(cdn, monkeypatch):
    import json
    cdn.files["/latest"] = json.dumps({
        "tag_name": "v9.9.9",
        "assets": [
            {"name": "SecureShare.zip", "browser_download_url": "u-plain-zip", "size": 1},
            {"name": "SecureShare-v9.9.9.zip", "browser_download_url": "u-zip", "size": 2},
            {"name": "SecureShare-linux-x64.tar.gz", "browser_download_url": "u-plain-tgz", "size": 3},
            {"name": "SecureShare-v9.9.9-linux-x64.tar.gz", "browser_download_url": "u-tgz", "size": 4},
            {"name": "SHA256SUMS.txt", "browser_download_url": "u-sums", "size": 5},
        ],
    }).encode()
    monkeypatch.setattr(updater, "GITHUB_API_URL", cdn.url("/latest"))
    rel = updater.fetch_latest_release()
    assert (rel.version, rel.win_download, rel.win_size) == ("9.9.9", "u-zip", 2)
    assert (rel.linux_download, rel.linux_size, rel.checksums_url) == ("u-tgz", 4, "u-sums")


def test_check_for_update_respects_skip_and_downgrade(cdn, monkeypatch):
    import json
    cdn.files["/latest"] = json.dumps({"tag_name": "v99.0.0", "assets": []}).encode()
    monkeypatch.setattr(updater, "GITHUB_API_URL", cdn.url("/latest"))
    monkeypatch.setattr(updater, "should_check_now", lambda: True)
    updater.clear_skipped()
    assert updater.check_for_update(force=False).version == "99.0.0"
    updater.skip_version("99.0.0")
    assert updater.check_for_update(force=False) is None       # skipped by user
    assert updater.check_for_update(force=True).version == "99.0.0"  # manual check ignores skip
    updater.clear_skipped()

    cdn.files["/latest"] = json.dumps({"tag_name": "v0.0.1", "assets": []}).encode()
    assert updater.check_for_update(force=True) is None


# ── Temp directory hygiene (B3) and single source of truth (B4) ─────

def _update_dirs():
    import tempfile
    from pathlib import Path
    return {p.name for p in Path(tempfile.gettempdir()).glob("secureshare_update_*")}


def test_failed_download_leaves_no_temp_dir(cdn, windows):
    before = _update_dirs()
    arc = make_zip({"SecureShare.exe": fake_pe()})
    binary, err = download_and_verify(_release(cdn, arc, "SecureShare-v9.9.9.zip", None, size=1))
    assert binary is None and "Size mismatch" in err
    assert _update_dirs() == before


def test_successful_download_is_cleaned_after_install(cdn, windows):
    before = _update_dirs()
    arc = make_zip({"SecureShare.exe": fake_pe()})
    sums = f"{hashlib.sha256(arc).hexdigest()}  SecureShare-v9.9.9.zip\n".encode()
    binary, _ = download_and_verify(_release(cdn, arc, "SecureShare-v9.9.9.zip", sums))
    assert binary.exists() and _update_dirs() != before
    updater._cleanup_download(binary)
    assert _update_dirs() == before


def test_update_check_only_asks_github(cdn, monkeypatch):
    import json
    cdn.files["/latest"] = json.dumps({"tag_name": "v0.0.1", "assets": []}).encode()
    monkeypatch.setattr(updater, "GITHUB_API_URL", cdn.url("/latest"))
    assert updater.check_for_update(force=True) is None
    assert cdn.requests == ["/latest"]
    assert not hasattr(updater, "RELAY_VERSION_URL")


def test_tar_extraction_uses_data_filter(tmp_path, recwarn):
    arc = tmp_path / "a.tar.gz"
    arc.write_bytes(make_tar({"SecureShare": b"\x7fELF"}))
    out, err = _extract_tar(arc, tmp_path / "x")
    assert err == ""
    assert not [w for w in recwarn if issubclass(w.category, DeprecationWarning) and "tar" in str(w.message)]
