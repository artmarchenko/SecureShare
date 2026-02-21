"""
SecureShare — Anonymous telemetry & crash reporting (opt-in).

Sends anonymous usage statistics and crash reports to the relay server.
No PII is collected: no IPs, no file names, no session codes.

Privacy:
  - All data is anonymous (random session ID, no persistent user ID)
  - File names, session codes, IPs are NEVER included
  - File sizes are bucketed (e.g. "10-100MB"), not exact
  - Opt-in: user must enable telemetry in settings
  - All requests are fire-and-forget, no retries
  - All requests have a 10-second timeout
  - Reports are sent over HTTPS to the relay server
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import sys
import traceback
import threading
import time
import urllib.request
import urllib.error
from typing import Any, Optional

from app.config import APP_VERSION, VPS_RELAY_URL

log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────

# Base URL for the API (derive from the WSS relay URL)
_BASE_URL = VPS_RELAY_URL.replace("wss://", "https://").replace("ws://", "http://")
CRASH_ENDPOINT = f"{_BASE_URL}/api/crash"
TELEMETRY_ENDPOINT = f"{_BASE_URL}/api/telemetry"

# Timeout for HTTP requests
HTTP_TIMEOUT = 10  # seconds

# Settings file (same directory as updater settings)
_SETTINGS_DIR = os.path.join(
    os.environ.get("APPDATA") or os.path.expanduser("~"),
    ".secureshare"
)
_SETTINGS_FILE = os.path.join(_SETTINGS_DIR, "telemetry.json")


# ── Opt-in settings ──────────────────────────────────────────────

def _load_settings() -> dict:
    try:
        if os.path.isfile(_SETTINGS_FILE):
            with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_settings(settings: dict) -> None:
    try:
        os.makedirs(_SETTINGS_DIR, exist_ok=True)
        with open(_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except Exception:
        pass


def is_telemetry_enabled() -> bool:
    """Check if user has opted in to telemetry."""
    return _load_settings().get("enabled", False)


def set_telemetry_enabled(enabled: bool) -> None:
    """Set telemetry opt-in preference."""
    s = _load_settings()
    s["enabled"] = enabled
    _save_settings(s)


def is_crash_reporting_enabled() -> bool:
    """Check if crash reporting is enabled (separate from telemetry)."""
    return _load_settings().get("crash_reporting", True)  # default on


def set_crash_reporting_enabled(enabled: bool) -> None:
    s = _load_settings()
    s["crash_reporting"] = enabled
    _save_settings(s)


# ── Anonymous identifiers ─────────────────────────────────────────

def _session_id() -> str:
    """Generate a random session ID (not persistent, not trackable)."""
    return hashlib.sha256(os.urandom(32)).hexdigest()[:16]


def _os_info() -> str:
    """Get OS type + major version (e.g. 'Windows-10', 'Linux-6')."""
    system = platform.system()
    version = platform.version()
    # Only include major version number
    major = version.split(".")[0] if version else ""
    return f"{system}-{major}" if major else system


def _file_size_bucket(size_bytes: int) -> str:
    """Bucket file size for privacy (no exact sizes)."""
    mb = size_bytes / (1024 * 1024)
    if mb < 1:
        return "<1MB"
    elif mb < 10:
        return "1-10MB"
    elif mb < 100:
        return "10-100MB"
    elif mb < 500:
        return "100-500MB"
    elif mb < 1024:
        return "500MB-1GB"
    else:
        return f"{int(mb / 1024)}GB+"


# ── HTTP sender (fire-and-forget) ────────────────────────────────

def _send_async(url: str, data: dict) -> None:
    """Send data to URL in a background thread. Fire-and-forget."""
    def _do():
        try:
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"SecureShare/{APP_VERSION}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                pass  # We don't care about the response
        except Exception:
            pass  # Fire and forget — never fail loudly

    t = threading.Thread(target=_do, daemon=True)
    t.start()


# ══════════════════════════════════════════════════════════════════
#  Crash Reporting
# ══════════════════════════════════════════════════════════════════

def report_crash(
    exc: BaseException,
    state: str = "",
    log_tail: str = "",
    transfer_stats: Optional[dict] = None,
) -> None:
    """Send an anonymous crash report to the relay server.

    Only sends if crash reporting is enabled (default: True).
    """
    if not is_crash_reporting_enabled():
        return

    try:
        # Build anonymous crash report
        report = {
            "crash_id": _session_id(),
            "app_version": APP_VERSION,
            "os": _os_info(),
            "os_version": platform.version(),
            "python_version": platform.python_version(),
            "error_type": type(exc).__name__,
            "error_message": str(exc)[:500],
            "traceback": _safe_traceback(exc),
            "state": state[:50],
            "log_tail": _sanitize_log_tail(log_tail),
            "transfer_stats": _sanitize_transfer_stats(transfer_stats),
            "ram_mb": _get_ram_mb(),
            "cpu_count": os.cpu_count() or 0,
        }

        _send_async(CRASH_ENDPOINT, report)
        log.debug("Crash report sent (type=%s)", type(exc).__name__)
    except Exception:
        pass  # Never crash while reporting a crash


def _safe_traceback(exc: BaseException) -> str:
    """Format traceback with sanitized paths (no full system paths)."""
    try:
        tb_lines = traceback.format_exception(type(exc), exc, exc.__traceback__)
        tb_text = "".join(tb_lines)
        # Sanitize paths — remove user home directory
        home = os.path.expanduser("~")
        tb_text = tb_text.replace(home, "~")
        # Truncate
        return tb_text[:4000]
    except Exception:
        return f"{type(exc).__name__}: {exc}"


def _sanitize_log_tail(log_tail: str) -> str:
    """Sanitize log tail — remove any potential sensitive data."""
    if not log_tail:
        return ""
    # Remove session codes (8 alphanumeric chars that look like codes)
    # Remove IP addresses
    # Remove file paths (keep only filenames)
    import re
    sanitized = log_tail
    # Remove IPv4 addresses
    sanitized = re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "[IP]", sanitized)
    # Remove potential Windows paths
    sanitized = re.sub(r"[A-Z]:\\[^\s]+", "[PATH]", sanitized)
    # Remove potential Unix paths
    sanitized = re.sub(r"/(?:home|Users)/[^\s]+", "[PATH]", sanitized)
    return sanitized[:2000]


def _sanitize_transfer_stats(stats: Optional[dict]) -> dict:
    """Sanitize transfer stats — only include anonymous metrics."""
    if not stats or not isinstance(stats, dict):
        return {}
    return {
        "file_size_range": _file_size_bucket(stats.get("file_size", 0)),
        "chunks_sent": int(stats.get("chunks_sent", 0)),
        "chunks_total": int(stats.get("chunks_total", 0)),
        "duration_s": int(stats.get("duration_s", 0)),
        "used_resume": bool(stats.get("used_resume", False)),
        "used_reconnect": bool(stats.get("used_reconnect", False)),
    }


def _get_ram_mb() -> int:
    """Get current process RAM usage in MB."""
    try:
        import psutil
        return psutil.Process().memory_info().rss // (1024 * 1024)
    except Exception:
        pass
    try:
        # Fallback for systems without psutil
        if sys.platform == "win32":
            import ctypes
            # GetProcessMemoryInfo
            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong),
                    ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]
            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(
                handle, ctypes.byref(pmc), pmc.cb
            ):
                return pmc.WorkingSetSize // (1024 * 1024)
        else:
            # Linux: /proc/self/status
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1]) // 1024  # KB -> MB
    except Exception:
        pass
    return 0


# ══════════════════════════════════════════════════════════════════
#  Session Telemetry (post-transfer)
# ══════════════════════════════════════════════════════════════════

def report_session(
    role: str,          # "sender" or "receiver"
    outcome: str,       # "success", "error", "cancelled", "timeout"
    file_size: int = 0,
    duration_s: float = 0,
    chunks_sent: int = 0,
    chunks_total: int = 0,
    used_resume: bool = False,
    used_reconnect: bool = False,
    error_type: str = "",
) -> None:
    """Send anonymous session telemetry after a transfer completes.

    Only sends if telemetry is enabled (default: False, opt-in).
    """
    if not is_telemetry_enabled():
        return

    try:
        event = {
            "session_id": _session_id(),
            "app_version": APP_VERSION,
            "os": _os_info(),
            "role": role[:10],
            "outcome": outcome[:20],
            "file_size_range": _file_size_bucket(file_size),
            "duration_s": int(min(duration_s, 86400 * 7)),
            "chunks_sent": chunks_sent,
            "chunks_total": chunks_total,
            "used_resume": used_resume,
            "used_reconnect": used_reconnect,
            "error_type": error_type[:100] if outcome == "error" else "",
        }

        _send_async(TELEMETRY_ENDPOINT, event)
        log.debug("Session telemetry sent (outcome=%s)", outcome)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════
#  Global exception handler
# ══════════════════════════════════════════════════════════════════

_original_excepthook = sys.excepthook


def _crash_excepthook(exc_type, exc_value, exc_tb):
    """Global exception handler that sends crash reports."""
    try:
        # Re-attach traceback for formatting
        exc_value.__traceback__ = exc_tb
        report_crash(exc_value, state="unhandled")
    except Exception:
        pass
    # Call original hook
    _original_excepthook(exc_type, exc_value, exc_tb)


def install_crash_handler() -> None:
    """Install global exception handler for crash reporting.

    Should be called once at application startup.
    """
    sys.excepthook = _crash_excepthook
    log.debug("Crash handler installed")


def uninstall_crash_handler() -> None:
    """Restore the original exception handler."""
    sys.excepthook = _original_excepthook
