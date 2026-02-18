"""
SecureShare — Cloudflare Tunnel manager.

cloudflared.exe is bundled inside the PyInstaller package (tools/ dir).
No runtime download needed.

Usage:
    tunnel = CloudflareTunnel()
    url = tunnel.start(local_port=8765, on_status=log_fn)
    # url  →  "https://xyz.trycloudflare.com"  or  None on failure
    tunnel.stop()
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import threading
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────
_CF_EXE_NAME = "cloudflared.exe" if os.name == "nt" else "cloudflared"
# Tunnel URLs always have at least one hyphen in the subdomain,
# e.g. "evolution-trustee-created-resumes.trycloudflare.com"
# "api.trycloudflare.com" is the API endpoint — must NOT match.
_URL_PATTERN = re.compile(r"https://[a-z0-9][a-z0-9]*-[a-z0-9][a-z0-9\-]*\.trycloudflare\.com")

StatusCB = Callable[[str], None]


# ── Locate cloudflared ─────────────────────────────────────────────

def _is_valid_pe(path: Path) -> bool:
    """Check that the file is a real Windows PE executable (starts with 'MZ')."""
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except Exception:
        return False


def _find_cloudflared() -> Optional[Path]:
    """
    Return path to a working cloudflared binary.

    Search order:
      1. Bundled inside PyInstaller (_MEIPASS/tools/cloudflared.exe)
      2. Bundled at _MEIPASS root
      3. Previously extracted to %APPDATA%\\SecureShare\\cloudflared.exe
    """
    # 1 & 2 — PyInstaller bundle
    if hasattr(sys, "_MEIPASS"):
        for candidate in [
            Path(sys._MEIPASS) / "tools" / _CF_EXE_NAME,
            Path(sys._MEIPASS) / _CF_EXE_NAME,
        ]:
            if candidate.exists() and (os.name != "nt" or _is_valid_pe(candidate)):
                log.info("Using bundled cloudflared: %s", candidate)
                return candidate

    # 3 — extracted copy (legacy / dev mode)
    appdata = Path(os.environ.get("APPDATA", Path.home())) / "SecureShare"
    cached = appdata / _CF_EXE_NAME
    if cached.exists() and cached.stat().st_size > 5_000_000:
        if os.name != "nt" or _is_valid_pe(cached):
            log.info("Using cached cloudflared: %s", cached)
            return cached

    return None


# ════════════════════════════════════════════════════════════════════
#  CloudflareTunnel
# ════════════════════════════════════════════════════════════════════

class CloudflareTunnel:
    """
    Start a Cloudflare quick tunnel exposing localhost:port publicly.

    The tunnel process is kept alive for the duration of the transfer.
    Call stop() when done.
    """

    def __init__(self):
        self._process: Optional[subprocess.Popen] = None
        self._url: Optional[str] = None
        self._url_event = threading.Event()
        self._reader_thread: Optional[threading.Thread] = None

    # ── Public API ─────────────────────────────────────────────────

    def start(
        self,
        local_port: int,
        on_status: Optional[StatusCB] = None,
    ) -> Optional[str]:
        """
        Start the tunnel.  Returns the public URL or None if failed.
        Blocks until the URL is available (max 30 s).
        """
        exe = _find_cloudflared()
        if exe is None:
            msg = "❌ cloudflared не знайдено — CF Tunnel недоступний"
            log.error(msg)
            if on_status:
                on_status(msg)
            return None

        cmd = [
            str(exe),
            "tunnel",
            "--url", f"http://localhost:{local_port}",
            "--no-autoupdate",
        ]

        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NO_WINDOW  # no console popup

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=creationflags,
            )
        except Exception as exc:
            log.error("Failed to start cloudflared: %s", exc)
            if on_status:
                on_status(f"❌ cloudflared: {exc}")
            return None

        self._reader_thread = threading.Thread(
            target=self._reader, daemon=True, name="cf-reader"
        )
        self._reader_thread.start()

        if on_status:
            on_status("🌐 Cloudflare: відкриваю тунель...")

        if self._url_event.wait(timeout=30):
            if on_status:
                on_status(f"🌐 Cloudflare тунель: {self._url}")
            return self._url

        # Timeout
        log.warning("cloudflared did not provide URL within 30s")
        if on_status:
            on_status("❌ Cloudflare: тунель не відкрився за 30 с")
        self.stop()
        return None

    def stop(self) -> None:
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None
        self._url = None
        self._url_event.clear()

    # ── Internal ───────────────────────────────────────────────────

    def _reader(self) -> None:
        """Read cloudflared stdout/stderr and extract the public URL."""
        try:
            for line in self._process.stdout:
                log.debug("cloudflared: %s", line.rstrip())
                m = _URL_PATTERN.search(line)
                if m and not self._url:
                    self._url = m.group(0)
                    self._url_event.set()
        except Exception:
            pass
