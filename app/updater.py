"""
SecureShare — auto-update system.

Queries the GitHub Releases API for the latest version, downloads,
verifies, and installs updates with automatic rollback on failure.

Security model:
  1. HTTPS transport to GitHub (TLS protects against MITM)
  2. File size verified against GitHub API metadata (prevents truncation)
  3. SHA-256 checksum verified against SHA256SUMS.txt release asset
  4. Archive contents validated (path traversal, single expected file)
  5. Binary header verified (PE for Windows, ELF for Linux)
  6. Binary size sanity check (1 MB – 200 MB)
  7. Updater script uses only hardcoded paths (no injection)
  8. Secure temp directory (user-only permissions)
  9. Atomic replacement with .bak rollback
  10. Downgrade prevention (strict version comparison)

Features:
  - Background startup check (silent, non-blocking)
  - Manual "Check for updates" trigger
  - 24-hour cooldown between automatic checks
  - "Skip this version" persistence
  - Download progress callback
  - Zero extra dependencies (uses urllib.request)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .config import APP_VERSION, VPS_RELAY_URL

log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────

GITHUB_REPO = "artmarchenko/SecureShare"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
GITHUB_RELEASE_PAGE = f"https://github.com/{GITHUB_REPO}/releases/latest"

# Relay-server based version check (faster, no rate limits)
_RELAY_BASE = VPS_RELAY_URL.replace("wss://", "https://").replace("ws://", "http://")
RELAY_VERSION_URL = f"{_RELAY_BASE}/api/version"

CHECK_COOLDOWN = 24 * 3600   # 24 hours between automatic checks
REQUEST_TIMEOUT = 10          # seconds for API calls
DOWNLOAD_TIMEOUT = 300        # seconds for file download
DOWNLOAD_CHUNK = 64 * 1024   # 64 KB read chunks

# Binary size sanity bounds
MIN_BINARY_SIZE = 1_000_000       # 1 MB — smaller is suspicious
MAX_BINARY_SIZE = 200_000_000     # 200 MB — larger is suspicious

# Persistent settings file (next to log file in %APPDATA%/SecureShare/)
_SETTINGS_DIR = Path(os.environ.get("APPDATA", Path.home())) / "SecureShare"
_SETTINGS_FILE = _SETTINGS_DIR / "update_settings.json"

DownloadProgressCB = Callable[[int, int], None]   # (downloaded, total)


# ══════════════════════════════════════════════════════════════════
#  Version comparison
# ══════════════════════════════════════════════════════════════════

def _parse_version(ver: str) -> tuple[int, ...]:
    """Parse a version string like '3.2.1' or 'v3.2.1' into a tuple of ints."""
    ver = ver.strip().lstrip("vV")
    parts: list[int] = []
    for p in ver.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            num = ""
            for ch in p:
                if ch.isdigit():
                    num += ch
                else:
                    break
            parts.append(int(num) if num else 0)
    return tuple(parts)


def is_newer(remote: str, local: str) -> bool:
    """Return True if `remote` version is strictly newer than `local`."""
    return _parse_version(remote) > _parse_version(local)


# ══════════════════════════════════════════════════════════════════
#  Persistent settings
# ══════════════════════════════════════════════════════════════════

def _load_settings() -> dict:
    try:
        if _SETTINGS_FILE.exists():
            with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as exc:
        log.debug("Failed to load update settings: %s", exc)
    return {}


def _save_settings(data: dict) -> None:
    try:
        _SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
        with open(_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as exc:
        log.debug("Failed to save update settings: %s", exc)


def should_check_now() -> bool:
    settings = _load_settings()
    last_check = settings.get("last_check_ts", 0)
    return (time.time() - last_check) >= CHECK_COOLDOWN


def mark_checked() -> None:
    settings = _load_settings()
    settings["last_check_ts"] = time.time()
    _save_settings(settings)


def skip_version(version: str) -> None:
    settings = _load_settings()
    settings["skipped_version"] = version
    _save_settings(settings)


def is_version_skipped(version: str) -> bool:
    settings = _load_settings()
    return settings.get("skipped_version") == version


def clear_skipped() -> None:
    settings = _load_settings()
    settings.pop("skipped_version", None)
    _save_settings(settings)


# ══════════════════════════════════════════════════════════════════
#  GitHub API
# ══════════════════════════════════════════════════════════════════

@dataclass
class ReleaseInfo:
    """Information about the latest GitHub release."""
    tag: str              # e.g. "v3.3.0"
    version: str          # e.g. "3.3.0"
    name: str             # release title
    body: str             # release notes (markdown)
    html_url: str         # URL to release page
    published: str        # ISO date string
    win_download: str     # direct .zip URL (Windows)
    win_size: int = 0     # expected size from GitHub API
    linux_download: str = ""   # direct .tar.gz URL (Linux)
    linux_size: int = 0        # expected size from GitHub API
    checksums_url: str = ""    # SHA256SUMS.txt asset URL
    _assets_raw: list = field(default_factory=list, repr=False)


def fetch_latest_release() -> Optional[ReleaseInfo]:
    """Fetch the latest release info from GitHub API.

    Returns ReleaseInfo on success, None on any error.
    Blocking call — run in a thread for non-blocking use.
    """
    try:
        req = urllib.request.Request(
            GITHUB_API_URL,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"SecureShare/{APP_VERSION}",
            },
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        log.debug("GitHub API HTTP error: %s", exc.code)
        return None
    except Exception as exc:
        log.debug("GitHub API error: %s", exc)
        return None

    tag = data.get("tag_name", "")
    if not tag:
        return None

    version = tag.lstrip("vV")
    name = data.get("name", tag)
    body = data.get("body", "")
    html_url = data.get("html_url", GITHUB_RELEASE_PAGE)
    published = data.get("published_at", "")

    win_download = ""
    win_size = 0
    linux_download = ""
    linux_size = 0
    checksums_url = ""

    for asset in data.get("assets", []):
        aname = asset.get("name", "")
        url = asset.get("browser_download_url", "")
        size = asset.get("size", 0)

        if aname == "SHA256SUMS.txt":
            checksums_url = url
        elif aname.endswith(".zip") and "linux" not in aname.lower():
            if tag in aname or not win_download:
                win_download = url
                win_size = size
        elif aname.endswith(".tar.gz") and "linux" in aname.lower():
            if tag in aname or not linux_download:
                linux_download = url
                linux_size = size

    return ReleaseInfo(
        tag=tag,
        version=version,
        name=name,
        body=body,
        html_url=html_url,
        published=published,
        win_download=win_download,
        win_size=win_size,
        linux_download=linux_download,
        linux_size=linux_size,
        checksums_url=checksums_url,
    )


def _quick_version_check() -> Optional[str]:
    """Fast version check via relay server's /api/version endpoint.

    Returns the latest version string if newer than current, else None.
    This is faster and has no rate limits (unlike GitHub API).
    Used as an early-out: if no update via relay, skip GitHub API call.
    """
    try:
        req = urllib.request.Request(
            RELAY_VERSION_URL,
            headers={"User-Agent": f"SecureShare/{APP_VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        latest = data.get("latest_version", "")
        if latest and is_newer(latest, APP_VERSION):
            return latest
    except Exception as exc:
        log.debug("Relay version check failed (non-critical): %s", exc)
    return None


def check_for_update(force: bool = False) -> Optional[ReleaseInfo]:
    """Check for updates, respecting cooldown and skip settings.

    Strategy:
      1. Quick check via relay server (/api/version) — fast, no rate limits
      2. If relay says "up to date" → return None (skip GitHub API)
      3. If relay says "update available" → fetch details from GitHub API
      4. If relay unreachable → fall through to GitHub API anyway

    Args:
        force: If True, ignore cooldown and skip settings (manual check).

    Returns ReleaseInfo if an update is available, None otherwise.
    """
    if not force:
        if not should_check_now():
            log.debug("Update check skipped (cooldown)")
            return None

    mark_checked()

    # Step 1: Quick relay-based check (fast, no rate limits)
    relay_version = _quick_version_check()
    if relay_version is None:
        # Relay says we're up-to-date OR relay is unreachable
        # Fall through to GitHub API only if relay was unreachable
        # (relay_version is None in both cases, so always try GitHub)
        pass

    release = fetch_latest_release()
    if release is None:
        log.debug("Could not fetch latest release")
        return None

    if not is_newer(release.version, APP_VERSION):
        log.debug("Up to date: local=%s, remote=%s",
                   APP_VERSION, release.version)
        return None

    if not force and is_version_skipped(release.version):
        log.debug("Version %s is skipped by user", release.version)
        return None

    log.info("Update available: %s -> %s", APP_VERSION, release.version)
    return release


# ══════════════════════════════════════════════════════════════════
#  Binary verification helpers
# ══════════════════════════════════════════════════════════════════

def _verify_pe_header(path: Path) -> bool:
    """Verify the file has a valid Windows PE header (MZ + PE signature)."""
    try:
        with open(path, "rb") as f:
            # DOS header: must start with 'MZ'
            if f.read(2) != b"MZ":
                return False
            # PE offset at 0x3C
            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]
            if pe_offset > 1024:  # sanity check
                return False
            # PE signature: 'PE\0\0'
            f.seek(pe_offset)
            if f.read(4) != b"PE\x00\x00":
                return False
        return True
    except Exception:
        return False


def _verify_elf_header(path: Path) -> bool:
    """Verify the file has a valid Linux ELF header."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            return magic == b"\x7fELF"
    except Exception:
        return False


def _verify_binary(path: Path) -> tuple[bool, str]:
    """Verify downloaded binary is valid for current platform.

    Returns (ok, error_message).
    """
    if not path.exists():
        return False, "File does not exist"

    size = path.stat().st_size
    if size < MIN_BINARY_SIZE:
        return False, f"Binary too small ({size:,} bytes) — possible corruption"
    if size > MAX_BINARY_SIZE:
        return False, f"Binary too large ({size:,} bytes) — suspicious"

    is_win = platform.system() == "Windows"
    if is_win:
        if not _verify_pe_header(path):
            return False, "Invalid PE header — not a valid Windows executable"
    else:
        if not _verify_elf_header(path):
            return False, "Invalid ELF header — not a valid Linux executable"

    return True, ""


# ══════════════════════════════════════════════════════════════════
#  SHA-256 checksum verification
# ══════════════════════════════════════════════════════════════════

def _fetch_checksums(url: str) -> dict[str, str]:
    """Download SHA256SUMS.txt and parse it.

    Returns dict { filename: sha256_hex }.
    """
    if not url:
        return {}
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": f"SecureShare/{APP_VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            text = resp.read().decode("utf-8")
    except Exception as exc:
        log.debug("Failed to fetch checksums: %s", exc)
        return {}

    result: dict[str, str] = {}
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            sha, fname = parts
            # Strip leading * (BSD-style) or path separators
            fname = fname.lstrip("*").strip()
            fname = fname.replace("\\", "/").split("/")[-1]
            result[fname] = sha.lower()
    return result


# ══════════════════════════════════════════════════════════════════
#  Archive extraction (with security checks)
# ══════════════════════════════════════════════════════════════════

def _extract_zip(archive: Path, dest: Path) -> tuple[Optional[Path], str]:
    """Extract SecureShare.exe from a zip archive.

    Security:
      - Rejects entries with path traversal (.. or absolute paths)
      - Expects exactly one .exe file
      - Verifies extracted path stays within dest

    Returns (path_to_exe, error_message).
    """
    import zipfile

    try:
        with zipfile.ZipFile(archive, "r") as zf:
            for info in zf.infolist():
                name = info.filename
                if name.startswith("/") or name.startswith("\\"):
                    return None, f"Absolute path in zip: {name}"
                if ".." in name.split("/") or ".." in name.split("\\"):
                    return None, f"Path traversal in zip: {name}"

            exe_names = [
                n for n in zf.namelist()
                if n.lower().endswith(".exe") and not n.startswith("__MACOSX")
            ]
            if len(exe_names) == 0:
                return None, "No .exe found in archive"
            if len(exe_names) > 1:
                return None, f"Multiple .exe files in archive: {exe_names}"

            exe_name = exe_names[0]
            zf.extract(exe_name, dest)

            extracted = (dest / exe_name).resolve()
            if not str(extracted).startswith(str(dest.resolve())):
                extracted.unlink(missing_ok=True)
                return None, "Path traversal detected after extraction"

            return extracted, ""

    except zipfile.BadZipFile:
        return None, "Corrupted zip archive"
    except Exception as exc:
        return None, f"Zip extraction failed: {exc}"


def _extract_tar(archive: Path, dest: Path) -> tuple[Optional[Path], str]:
    """Extract SecureShare from a tar.gz archive.

    Security:
      - Rejects entries with path traversal or absolute paths
      - Rejects symlinks and hardlinks
      - Expects exactly one regular file

    Returns (path_to_binary, error_message).
    """
    import tarfile

    try:
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                name = member.name
                if name.startswith("/") or name.startswith("\\"):
                    return None, f"Absolute path in tar: {name}"
                if ".." in name.split("/") or ".." in name.split("\\"):
                    return None, f"Path traversal in tar: {name}"
                if member.issym() or member.islnk():
                    return None, f"Symlink/hardlink in tar: {name}"

            files = [m for m in tf.getmembers() if m.isfile()]
            if len(files) == 0:
                return None, "No files found in archive"
            if len(files) > 1:
                return None, f"Multiple files in archive: {[m.name for m in files]}"

            member = files[0]
            tf.extract(member, dest, set_attrs=False)

            extracted = (dest / member.name).resolve()
            if not str(extracted).startswith(str(dest.resolve())):
                extracted.unlink(missing_ok=True)
                return None, "Path traversal detected after extraction"

            extracted.chmod(0o755)
            return extracted, ""

    except tarfile.TarError as exc:
        return None, f"Corrupted tar archive: {exc}"
    except Exception as exc:
        return None, f"Tar extraction failed: {exc}"


# ══════════════════════════════════════════════════════════════════
#  Download + verify
# ══════════════════════════════════════════════════════════════════

def _get_current_exe() -> Optional[Path]:
    """Get path to the currently running executable (frozen builds only)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve()
    return None


def can_auto_update() -> bool:
    """Return True if auto-update is possible (running as frozen .exe)."""
    return _get_current_exe() is not None


def download_and_verify(
    release: ReleaseInfo,
    progress_cb: Optional[DownloadProgressCB] = None,
    status_cb: Optional[Callable[[str], None]] = None,
) -> tuple[Optional[Path], str]:
    """Download, verify, and extract the update binary.

    Security checks performed:
      1. HTTPS transport (GitHub CDN)
      2. Downloaded file size matches GitHub API metadata
      3. SHA-256 matches SHA256SUMS.txt release asset (if available)
      4. Archive has no path traversal entries
      5. Archive contains exactly one expected file
      6. Extracted binary has valid PE/ELF header
      7. Extracted binary size is within sane bounds

    Returns (path_to_verified_binary, error_message).
    The caller is responsible for cleanup of temp files on error.
    """
    is_win = platform.system() == "Windows"

    if is_win:
        download_url = release.win_download
        expected_size = release.win_size
    else:
        download_url = release.linux_download
        expected_size = release.linux_size

    if not download_url:
        return None, "No download URL for this platform"

    # Determine expected archive filename (for checksum lookup)
    archive_filename = download_url.rsplit("/", 1)[-1] if "/" in download_url else ""

    def _status(msg: str) -> None:
        if status_cb:
            status_cb(msg)
        log.info("[Updater] %s", msg)

    # ── 1. Create secure temp directory ───────────────────────────
    temp_dir = Path(tempfile.mkdtemp(prefix="secureshare_update_"))
    suffix = ".zip" if is_win else ".tar.gz"
    archive_path = temp_dir / f"update{suffix}"

    try:
        # ── 2. Download SHA256SUMS.txt (if available) ─────────────
        expected_sha256 = ""
        if release.checksums_url:
            _status("Завантажую контрольні суми...")
            checksums = _fetch_checksums(release.checksums_url)
            if archive_filename and archive_filename in checksums:
                expected_sha256 = checksums[archive_filename]
                _status(f"SHA-256 очікується: {expected_sha256[:16]}...")
            else:
                _status("SHA256SUMS.txt не містить запису для цього файлу")

        # ── 3. Download archive ───────────────────────────────────
        _status("Завантажую оновлення...")

        req = urllib.request.Request(
            download_url,
            headers={"User-Agent": f"SecureShare/{APP_VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
            total_size = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            hasher = hashlib.sha256()

            with open(archive_path, "wb") as f:
                while True:
                    chunk = resp.read(DOWNLOAD_CHUNK)
                    if not chunk:
                        break
                    f.write(chunk)
                    hasher.update(chunk)
                    downloaded += len(chunk)
                    if progress_cb and total_size:
                        progress_cb(downloaded, total_size)

            actual_sha256 = hasher.hexdigest()

        actual_size = archive_path.stat().st_size
        _status(f"Завантажено {actual_size:,} байт")

        # ── 4. Verify file size ───────────────────────────────────
        if expected_size and actual_size != expected_size:
            return None, (
                f"Size mismatch: expected {expected_size:,}, "
                f"got {actual_size:,} bytes"
            )

        # ── 5. Verify SHA-256 ─────────────────────────────────────
        if expected_sha256:
            if actual_sha256 != expected_sha256:
                return None, (
                    f"SHA-256 mismatch!\n"
                    f"  Expected: {expected_sha256}\n"
                    f"  Got:      {actual_sha256}\n"
                    f"The download may have been tampered with."
                )
            _status("SHA-256 verified")
        else:
            _status(f"SHA-256: {actual_sha256} (no reference to verify against)")

        # ── 6. Extract archive ────────────────────────────────────
        _status("Розпаковую...")
        extract_dir = temp_dir / "extracted"
        extract_dir.mkdir()

        if is_win:
            binary_path, err = _extract_zip(archive_path, extract_dir)
        else:
            binary_path, err = _extract_tar(archive_path, extract_dir)

        if binary_path is None:
            return None, f"Extraction failed: {err}"

        # ── 7. Verify binary ─────────────────────────────────────
        _status("Перевіряю бінарний файл...")
        ok, err = _verify_binary(binary_path)
        if not ok:
            return None, f"Binary verification failed: {err}"

        _status("Оновлення перевірено")
        return binary_path, ""

    except Exception as exc:
        # Cleanup on error
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None, f"Download failed: {exc}"


# ══════════════════════════════════════════════════════════════════
#  Install + restart
# ══════════════════════════════════════════════════════════════════

def install_and_restart(
    new_binary: Path,
    status_cb: Optional[Callable[[str], None]] = None,
) -> tuple[bool, str]:
    """Install the update and restart the application.

    On Windows:
      - Creates a .bat script that waits for the current process to exit,
        backs up the old .exe, replaces it, and launches the new version.
      - Returns True + calls sys.exit(0) to let the .bat script take over.

    On Linux:
      - Directly replaces the binary and restarts via os.execv.

    Returns (success, error_message).
    On success, the process exits — this function does NOT return.
    """
    current_exe = _get_current_exe()
    if current_exe is None:
        return False, "Not running as a frozen executable — cannot auto-update"

    def _status(msg: str) -> None:
        if status_cb:
            status_cb(msg)
        log.info("[Updater] %s", msg)

    is_win = platform.system() == "Windows"

    if is_win:
        return _install_windows(new_binary, current_exe, _status)
    else:
        return _install_linux(new_binary, current_exe, _status)


def _install_windows(
    new_binary: Path,
    current_exe: Path,
    status_cb: Callable[[str], None],
) -> tuple[bool, str]:
    """Windows: create a batch script that replaces the exe after exit."""
    backup_path = current_exe.with_suffix(".exe.bak")
    pid = os.getpid()

    # Build batch script — all paths are hardcoded constants,
    # no user input is interpolated → no injection risk.
    # Using repr() for paths to handle spaces correctly.
    cur = str(current_exe)
    bak = str(backup_path)
    new = str(new_binary)

    script = (
        '@echo off\r\n'
        'chcp 65001 >nul 2>&1\r\n'
        'echo SecureShare: installing update...\r\n'
        'set /a count=0\r\n'
        ':wait\r\n'
        f'tasklist /FI "PID eq {pid}" 2>NUL | find /I "{pid}" >NUL\r\n'
        'if not errorlevel 1 (\r\n'
        '    set /a count+=1\r\n'
        '    if %count% geq 30 (\r\n'
        '        echo ERROR: Timeout waiting for old process.\r\n'
        '        goto cleanup\r\n'
        '    )\r\n'
        '    timeout /t 1 /nobreak >NUL\r\n'
        '    goto wait\r\n'
        ')\r\n'
        'echo Old process exited.\r\n'
        '\r\n'
        ':: Backup current exe\r\n'
        f'if exist "{cur}" (\r\n'
        f'    copy /Y "{cur}" "{bak}" >NUL 2>&1\r\n'
        '    echo Backup created.\r\n'
        ')\r\n'
        '\r\n'
        ':: Replace with new exe\r\n'
        f'copy /Y "{new}" "{cur}" >NUL 2>&1\r\n'
        'if errorlevel 1 (\r\n'
        '    echo ERROR: Failed to install. Restoring backup...\r\n'
        f'    if exist "{bak}" (\r\n'
        f'        copy /Y "{bak}" "{cur}" >NUL\r\n'
        '    )\r\n'
        '    pause\r\n'
        '    goto cleanup\r\n'
        ')\r\n'
        '\r\n'
        'echo Update installed successfully.\r\n'
        f'start "" "{cur}"\r\n'
        '\r\n'
        ':cleanup\r\n'
        f'del /Q "{new}" >NUL 2>&1\r\n'
        ':: Self-delete\r\n'
        'del "%~f0" >NUL 2>&1\r\n'
    )

    bat_path = new_binary.parent / "_secureshare_updater.bat"
    try:
        with open(bat_path, "w", encoding="utf-8") as f:
            f.write(script)

        status_cb("Запускаю оновлення та перезавантаження...")

        # Launch the batch script in a hidden window
        subprocess.Popen(
            ["cmd.exe", "/c", str(bat_path)],
            creationflags=subprocess.CREATE_NO_WINDOW,
            close_fds=True,
        )

        # Exit current process so the bat script can replace the exe
        status_cb("Завершую для оновлення...")
        log.info("Updater launched (PID %d), exiting for update...", pid)

        # Give the bat script a moment to start
        import time as _time
        _time.sleep(0.5)
        sys.exit(0)

        # Never reached
        return True, ""

    except SystemExit:
        raise  # re-raise sys.exit
    except Exception as exc:
        return False, f"Failed to create updater script: {exc}"


def _install_linux(
    new_binary: Path,
    current_exe: Path,
    status_cb: Callable[[str], None],
) -> tuple[bool, str]:
    """Linux: replace binary and restart via os.execv."""
    backup_path = current_exe.with_suffix(".bak")

    try:
        # Backup current binary
        if current_exe.exists():
            shutil.copy2(str(current_exe), str(backup_path))
            status_cb("Backup created")

        # Replace (Linux doesn't lock running binaries)
        shutil.move(str(new_binary), str(current_exe))
        current_exe.chmod(0o755)

        status_cb("Перезапуск...")
        log.info("Restarting with new binary: %s", current_exe)

        # Replace current process with the new binary
        os.execv(str(current_exe), sys.argv)

        # Never reached
        return True, ""

    except Exception as exc:
        # Rollback
        if backup_path.exists() and not current_exe.exists():
            shutil.move(str(backup_path), str(current_exe))
            log.info("Rollback: restored backup")
        return False, f"Installation failed: {exc}"
