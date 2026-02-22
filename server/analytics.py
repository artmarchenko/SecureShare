"""
SecureShare Relay — Analytics & Crash Reporting.

Collects anonymous usage statistics and crash reports.
All data is stored in append-only JSONL files with auto-rotation.

Security:
  - No PII stored (no IPs, no file names, no session codes)
  - API key verified with timing-safe comparison (hmac.compare_digest)
  - Rate limiting per IP on all POST endpoints
  - Strict input validation and size limits on all incoming data
  - Fixed-size in-memory counters with automatic purge
  - Disk usage capped via max file size + rotation
  - All string fields sanitized and length-limited
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("relay.analytics")

# ── Configuration ─────────────────────────────────────────────────

DATA_DIR = Path(os.getenv("RELAY_DATA_DIR", "/data"))
ADMIN_KEY = os.getenv("RELAY_ADMIN_KEY", "")  # REQUIRED for /api/stats
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Limits
MAX_CRASH_BODY = 32 * 1024       # 32 KB max crash report
MAX_TELEMETRY_BODY = 4 * 1024    # 4 KB max telemetry event
MAX_JSONL_SIZE = 50 * 1024 * 1024  # 50 MB — rotate after this
MAX_HOURLY_BUCKETS = 30 * 24     # 30 days of hourly data in memory
MAX_STRING_LEN = 500             # max length for any string field
MAX_CRASHES_IN_MEMORY = 1000     # recent crashes kept in RAM
MAX_DICT_KEYS = 500              # max unique keys in distribution dicts

# Rate limits for POST endpoints (per IP)
CRASH_RATE_LIMIT = 5             # max crash reports per IP per hour
TELEMETRY_RATE_LIMIT = 10        # max telemetry events per IP per hour
ADMIN_FAIL_LIMIT = 10            # max failed auth attempts per IP per hour
ADMIN_LOCKOUT_SECONDS = 3600     # lockout duration after too many failures


# ── Helpers ───────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hour_key() -> str:
    """Current hour as 'YYYY-MM-DD-HH'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d-%H")


def _day_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _month_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _sanitize_str(value: Any, max_len: int = MAX_STRING_LEN) -> str:
    """Sanitize a string field: type check, strip, truncate."""
    if not isinstance(value, str):
        value = str(value) if value is not None else ""
    # Remove null bytes and control chars (except newline/tab for tracebacks)
    value = "".join(
        ch for ch in value
        if ch == "\n" or ch == "\t" or (ord(ch) >= 32 and ord(ch) != 127)
    )
    return value[:max_len].strip()


def _safe_incr(d: dict, key: str, limit: int = MAX_DICT_KEYS) -> None:
    """Increment a counter in a dict, but refuse new keys if limit reached.

    Prevents memory exhaustion from attacker-supplied unique keys.
    Existing keys are always incremented regardless of limit.
    """
    if key in d:
        d[key] += 1
    elif len(d) < limit:
        d[key] = 1
    # else: silently drop — dict is full, new keys are rejected


def _sanitize_int(value: Any, min_val: int = 0,
                  max_val: int = 2**53) -> int:
    """Sanitize an integer field."""
    try:
        v = int(value)
        return max(min_val, min(v, max_val))
    except (TypeError, ValueError):
        return 0


# ── API Rate Limiter ──────────────────────────────────────────────

class APIRateLimiter:
    """Per-IP rate limiter for API endpoints."""

    def __init__(self):
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._admin_fails: dict[str, list[float]] = defaultdict(list)

    def check(self, ip: str, limit: int) -> bool:
        """Return True if request is allowed."""
        now = time.monotonic()
        key = ip
        self._buckets[key] = [
            t for t in self._buckets[key] if now - t < 3600
        ]
        if len(self._buckets[key]) >= limit:
            return False
        self._buckets[key].append(now)
        return True

    def record_admin_fail(self, ip: str) -> None:
        """Record a failed admin auth attempt."""
        now = time.monotonic()
        self._admin_fails[ip] = [
            t for t in self._admin_fails.get(ip, []) if now - t < ADMIN_LOCKOUT_SECONDS
        ]
        self._admin_fails[ip].append(now)

    def is_admin_locked(self, ip: str) -> bool:
        """Return True if IP is locked out from admin endpoints."""
        now = time.monotonic()
        fails = [
            t for t in self._admin_fails.get(ip, [])
            if now - t < ADMIN_LOCKOUT_SECONDS
        ]
        self._admin_fails[ip] = fails
        return len(fails) >= ADMIN_FAIL_LIMIT

    def cleanup(self) -> None:
        now = time.monotonic()
        stale = [k for k, v in self._buckets.items() if all(now - t > 3600 for t in v)]
        for k in stale:
            del self._buckets[k]
        stale = [k for k, v in self._admin_fails.items() if all(now - t > ADMIN_LOCKOUT_SECONDS for t in v)]
        for k in stale:
            del self._admin_fails[k]


# ── JSONL Writer ──────────────────────────────────────────────────

class JSONLWriter:
    """Append-only JSONL file writer with size-based rotation."""

    def __init__(self, base_name: str, data_dir: Path):
        self._base_name = base_name
        self._data_dir = data_dir

    def _current_path(self) -> Path:
        month = _month_key()
        return self._data_dir / f"{self._base_name}_{month}.jsonl"

    def append(self, record: dict) -> bool:
        """Append a JSON record. Returns True on success."""
        try:
            self._data_dir.mkdir(parents=True, exist_ok=True)
            path = self._current_path()
            # Check size — rotate if too large
            if path.exists() and path.stat().st_size > MAX_JSONL_SIZE:
                rotated = path.with_suffix(f".{int(time.time())}.jsonl")
                path.rename(rotated)
            line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            return True
        except Exception as exc:
            log.error("JSONL write failed (%s): %s", self._base_name, exc)
            return False

    def read_recent(self, max_lines: int = 200) -> list[dict]:
        """Read the most recent records from the current file."""
        path = self._current_path()
        if not path.exists():
            return []
        try:
            lines = path.read_text(encoding="utf-8").strip().splitlines()
            recent = lines[-max_lines:] if len(lines) > max_lines else lines
            result = []
            for line in recent:
                try:
                    result.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            return result
        except Exception as exc:
            log.error("JSONL read failed (%s): %s", self._base_name, exc)
            return []

    def list_files(self) -> list[str]:
        """List all JSONL files for this base name."""
        if not self._data_dir.exists():
            return []
        return sorted(
            f.name for f in self._data_dir.glob(f"{self._base_name}_*.jsonl")
        )

    def get_file_path(self, filename: str) -> Optional[Path]:
        """Get validated path to a specific log file. Returns None if invalid."""
        # Security: only allow files matching our pattern
        safe_name = Path(filename).name  # strip any path components
        if not safe_name.startswith(self._base_name + "_"):
            return None
        if not safe_name.endswith(".jsonl"):
            return None
        # No traversal characters
        if ".." in safe_name or "/" in safe_name or "\\" in safe_name:
            return None
        path = self._data_dir / safe_name
        if not path.exists():
            return None
        # Defense-in-depth: resolved path must be within data_dir
        if not str(path.resolve()).startswith(str(self._data_dir.resolve())):
            return None
        return path


# ══════════════════════════════════════════════════════════════════
#  StatsCollector
# ══════════════════════════════════════════════════════════════════

class StatsCollector:
    """Collects anonymous usage statistics in memory + periodic JSONL flush.

    Tracked metrics:
      - Lifetime totals (sessions, bytes, transfers, etc.)
      - Hourly buckets (for trend charts)
      - Transfer size distribution (histogram)
      - App version + OS distribution
      - Error type distribution
      - Peak concurrent rooms
    """

    def __init__(self, data_dir: Path):
        self._writer = JSONLWriter("stats", data_dir)
        self._start_time = time.monotonic()
        self._start_wall = _now_iso()

        # ── Lifetime counters ──────────────────────────────────
        self.lifetime = {
            "sessions_created": 0,
            "sessions_paired": 0,
            "sessions_timeout": 0,
            "sessions_completed": 0,     # completed relay (both sides disconnected normally)
            "bytes_relayed": 0,
            "rate_limit_hits": 0,
            "backpressure_events": 0,
            "data_limit_exceeded": 0,
            "connections_total": 0,
        }

        # ── Hourly buckets ─────────────────────────────────────
        # { "2026-02-21-14": { "sessions": 5, "bytes": 1234, ... } }
        self._hourly: dict[str, dict[str, int]] = defaultdict(
            lambda: {
                "sessions": 0,
                "paired": 0,
                "completed": 0,
                "timeout": 0,
                "bytes": 0,
                "connections": 0,
                "rate_limits": 0,
                "errors": 0,
            }
        )

        # ── Distributions ──────────────────────────────────────
        # Transfer size ranges (count per bucket)
        self._size_dist: dict[str, int] = defaultdict(int)  # "1-10MB": 5
        # Duration ranges
        self._duration_dist: dict[str, int] = defaultdict(int)
        # App version counts
        self._versions: dict[str, int] = defaultdict(int)
        # OS type counts
        self._os_dist: dict[str, int] = defaultdict(int)
        # Error type counts
        self._error_types: dict[str, int] = defaultdict(int)

        # ── Peak tracking ──────────────────────────────────────
        self.peak_concurrent_rooms = 0

        # ── Client telemetry events (processed) ───────────────
        self._client_events: dict[str, int] = defaultdict(int)

        # ── Restore from disk ─────────────────────────────────
        self._load_from_disk()

    # ── Restore from disk on startup ─────────────────────────

    def _load_from_disk(self) -> None:
        """Restore all counters from the last JSONL snapshot.

        Reads the most recent record and restores:
          - lifetime counters (sessions, bytes, etc.)
          - peak concurrent rooms
          - distributions (sizes, durations, versions, OS, errors)
          - client events
        """
        try:
            records = self._writer.read_recent(max_lines=1)
            if not records:
                log.info("Stats: no previous data on disk — starting fresh")
                return
            last = records[-1]

            # Restore lifetime counters
            saved_lifetime = last.get("lifetime", {})
            if isinstance(saved_lifetime, dict):
                for key in self.lifetime:
                    if key in saved_lifetime:
                        val = saved_lifetime[key]
                        if isinstance(val, (int, float)):
                            self.lifetime[key] = int(val)

            self.peak_concurrent_rooms = int(
                last.get("peak_rooms", 0)
            )

            # Restore distributions
            dist = last.get("distributions", {})
            if isinstance(dist, dict):
                for k, v in dist.get("transfer_size", {}).items():
                    self._size_dist[k] = int(v)
                for k, v in dist.get("transfer_duration", {}).items():
                    self._duration_dist[k] = int(v)
                for k, v in dist.get("app_versions", {}).items():
                    self._versions[k] = int(v)
                for k, v in dist.get("os_types", {}).items():
                    self._os_dist[k] = int(v)
                for k, v in dist.get("error_types", {}).items():
                    self._error_types[k] = int(v)

            # Restore client events
            events = last.get("client_events", {})
            if isinstance(events, dict):
                for k, v in events.items():
                    self._client_events[k] = int(v)

            log.info(
                "Stats: restored from disk — %d sessions, %.2f GB relayed",
                self.lifetime["sessions_completed"],
                self.lifetime["bytes_relayed"] / (1024 ** 3),
            )
        except Exception as exc:
            log.warning("Stats: failed to restore from disk: %s", exc)

    # ── Recording events ──────────────────────────────────────

    def record_connection(self) -> None:
        self.lifetime["connections_total"] += 1
        self._hourly[_hour_key()]["connections"] += 1

    def record_session_created(self) -> None:
        self.lifetime["sessions_created"] += 1
        self._hourly[_hour_key()]["sessions"] += 1

    def record_session_paired(self) -> None:
        self.lifetime["sessions_paired"] += 1
        self._hourly[_hour_key()]["paired"] += 1

    def record_session_timeout(self) -> None:
        self.lifetime["sessions_timeout"] += 1
        self._hourly[_hour_key()]["timeout"] += 1

    def record_session_completed(self, bytes_relayed: int,
                                 duration_s: float) -> None:
        self.lifetime["sessions_completed"] += 1
        self.lifetime["bytes_relayed"] += bytes_relayed
        hour = _hour_key()
        self._hourly[hour]["completed"] += 1
        self._hourly[hour]["bytes"] += bytes_relayed
        self._size_dist[_size_bucket(bytes_relayed)] += 1
        self._duration_dist[_duration_bucket(duration_s)] += 1

    def record_bytes_relayed(self, nbytes: int) -> None:
        """Increment bytes without completing session (for incremental tracking)."""
        self.lifetime["bytes_relayed"] += nbytes

    def record_rate_limit(self) -> None:
        self.lifetime["rate_limit_hits"] += 1
        self._hourly[_hour_key()]["rate_limits"] += 1

    def record_backpressure(self) -> None:
        self.lifetime["backpressure_events"] += 1

    def record_data_limit_exceeded(self) -> None:
        self.lifetime["data_limit_exceeded"] += 1

    def record_error(self, error_type: str) -> None:
        safe = _sanitize_str(error_type, 100)
        _safe_incr(self._error_types, safe)
        self._hourly[_hour_key()]["errors"] += 1

    def update_peak_rooms(self, active_rooms: int) -> None:
        if active_rooms > self.peak_concurrent_rooms:
            self.peak_concurrent_rooms = active_rooms

    def record_client_event(self, event: dict) -> None:
        """Process a client telemetry event (anonymous)."""
        # Record version + OS distribution
        version = _sanitize_str(event.get("app_version", ""), 20)
        os_type = _sanitize_str(event.get("os", ""), 30)
        outcome = _sanitize_str(event.get("outcome", ""), 20)

        if version:
            _safe_incr(self._versions, version)
        if os_type:
            _safe_incr(self._os_dist, os_type)
        if outcome:
            _safe_incr(self._client_events, outcome)

        # Record client-reported errors
        if outcome == "error":
            err_type = _sanitize_str(event.get("error_type", "unknown"), 100)
            _safe_incr(self._error_types, f"client:{err_type}")

        # Record if resume/reconnect was used
        if event.get("used_resume"):
            _safe_incr(self._client_events, "resume_used")
        if event.get("used_reconnect"):
            _safe_incr(self._client_events, "reconnect_used")

    # ── Queries ────────────────────────────────────────────────

    def get_summary(self) -> dict:
        """Return full stats summary for API/dashboard."""
        uptime_s = time.monotonic() - self._start_time
        uptime_h = uptime_s / 3600

        total_gb = self.lifetime["bytes_relayed"] / (1024 ** 3)
        success_rate = (
            self.lifetime["sessions_completed"]
            / max(self.lifetime["sessions_paired"], 1) * 100
        )

        return {
            "generated_at": _now_iso(),
            "server_start": self._start_wall,
            "uptime_hours": round(uptime_h, 1),
            "lifetime": {
                **self.lifetime,
                "bytes_relayed_gb": round(total_gb, 2),
                "success_rate_pct": round(success_rate, 1),
                "peak_concurrent_rooms": self.peak_concurrent_rooms,
            },
            "hourly": dict(
                sorted(self._hourly.items())[-48:]  # last 48 hours
            ),
            "distributions": {
                "transfer_size": dict(self._size_dist),
                "transfer_duration": dict(self._duration_dist),
                "app_versions": dict(
                    sorted(self._versions.items(),
                           key=lambda x: x[1], reverse=True)[:20]
                ),
                "os_types": dict(self._os_dist),
                "error_types": dict(
                    sorted(self._error_types.items(),
                           key=lambda x: x[1], reverse=True)[:20]
                ),
            },
            "client_events": dict(self._client_events),
        }

    # ── Persistence ────────────────────────────────────────────

    def flush_hourly(self) -> None:
        """Flush current stats snapshot to JSONL (called every hour).

        Includes all data needed to restore state after restart.
        """
        record = {
            "ts": _now_iso(),
            "hour": _hour_key(),
            "lifetime": dict(self.lifetime),
            "hourly_current": dict(self._hourly.get(_hour_key(), {})),
            "peak_rooms": self.peak_concurrent_rooms,
            "distributions": {
                "transfer_size": dict(self._size_dist),
                "transfer_duration": dict(self._duration_dist),
                "app_versions": dict(self._versions),
                "os_types": dict(self._os_dist),
                "error_types": dict(self._error_types),
            },
            "client_events": dict(self._client_events),
        }
        self._writer.append(record)
        self._purge_old_buckets()

    def _purge_old_buckets(self) -> None:
        """Remove hourly buckets older than MAX_HOURLY_BUCKETS hours."""
        keys = sorted(self._hourly.keys())
        if len(keys) > MAX_HOURLY_BUCKETS:
            for k in keys[:-MAX_HOURLY_BUCKETS]:
                del self._hourly[k]


# ══════════════════════════════════════════════════════════════════
#  CrashStore
# ══════════════════════════════════════════════════════════════════

class CrashStore:
    """Stores crash reports in JSONL with in-memory recent cache."""

    def __init__(self, data_dir: Path):
        self._writer = JSONLWriter("crashes", data_dir)
        self._recent: list[dict] = []

    def add(self, report: dict) -> bool:
        """Validate and store a crash report. Returns True on success."""
        # ── Strict schema validation ──────────────────────────
        sanitized = {
            "ts": _now_iso(),
            "crash_id": _sanitize_str(report.get("crash_id", ""), 64),
            "app_version": _sanitize_str(report.get("app_version", ""), 20),
            "os": _sanitize_str(report.get("os", ""), 50),
            "os_version": _sanitize_str(report.get("os_version", ""), 50),
            "python_version": _sanitize_str(report.get("python_version", ""), 20),
            "error_type": _sanitize_str(report.get("error_type", ""), 200),
            "error_message": _sanitize_str(report.get("error_message", ""), 500),
            "traceback": _sanitize_str(report.get("traceback", ""), 4000),
            "state": _sanitize_str(report.get("state", ""), 50),
            "log_tail": _sanitize_str(report.get("log_tail", ""), 2000),
            "transfer_stats": _sanitize_transfer_stats(
                report.get("transfer_stats")
            ),
            "ram_mb": _sanitize_int(report.get("ram_mb"), 0, 1_000_000),
            "cpu_count": _sanitize_int(report.get("cpu_count"), 0, 1024),
        }

        # Require at least some useful data
        if not sanitized["error_type"] and not sanitized["error_message"]:
            return False

        ok = self._writer.append(sanitized)
        if ok:
            self._recent.append(sanitized)
            # Keep only recent in memory
            if len(self._recent) > MAX_CRASHES_IN_MEMORY:
                self._recent = self._recent[-MAX_CRASHES_IN_MEMORY:]
        return ok

    def get_recent(self, hours: int = 48,
                   max_count: int = 100) -> list[dict]:
        """Get recent crashes, optionally filtered by time window."""
        if not self._recent:
            # Try loading from file
            self._recent = self._writer.read_recent(MAX_CRASHES_IN_MEMORY)

        if hours <= 0:
            return self._recent[-max_count:]

        cutoff_ts = time.time() - hours * 3600
        cutoff_iso = datetime.fromtimestamp(
            cutoff_ts, timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        filtered = [
            r for r in self._recent
            if r.get("ts", "") >= cutoff_iso
        ]
        return filtered[-max_count:]

    def get_grouped(self, hours: int = 48) -> dict:
        """Get crashes grouped by error type for analysis."""
        recent = self.get_recent(hours, max_count=500)
        groups: dict[str, list[dict]] = defaultdict(list)
        for r in recent:
            key = r.get("error_type", "unknown")
            groups[key].append(r)

        return {
            "total": len(recent),
            "hours": hours,
            "generated_at": _now_iso(),
            "groups": {
                k: {
                    "count": len(v),
                    "latest": v[-1] if v else None,
                    "versions": list(set(
                        r.get("app_version", "?") for r in v
                    )),
                    "os_types": list(set(
                        r.get("os", "?") for r in v
                    )),
                }
                for k, v in sorted(
                    groups.items(), key=lambda x: len(x[1]), reverse=True
                )
            },
        }

    def list_files(self) -> list[str]:
        return self._writer.list_files()

    def get_file_path(self, filename: str) -> Optional[Path]:
        return self._writer.get_file_path(filename)


def _sanitize_transfer_stats(raw: Any) -> dict:
    """Sanitize transfer_stats sub-object."""
    if not isinstance(raw, dict):
        return {}
    return {
        "file_size_range": _sanitize_str(raw.get("file_size_range", ""), 20),
        "chunks_sent": _sanitize_int(raw.get("chunks_sent")),
        "chunks_total": _sanitize_int(raw.get("chunks_total")),
        "duration_s": _sanitize_int(raw.get("duration_s"), 0, 86400 * 7),
        "used_resume": bool(raw.get("used_resume")),
        "used_reconnect": bool(raw.get("used_reconnect")),
    }


# ── Distribution bucket helpers ───────────────────────────────

def _size_bucket(nbytes: int) -> str:
    mb = nbytes / (1024 * 1024)
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


def _duration_bucket(seconds: float) -> str:
    if seconds < 10:
        return "<10s"
    elif seconds < 60:
        return "10-60s"
    elif seconds < 300:
        return "1-5min"
    elif seconds < 1800:
        return "5-30min"
    elif seconds < 3600:
        return "30-60min"
    else:
        return "60min+"


# ══════════════════════════════════════════════════════════════════
#  LandingAnalytics — page views, unique visitors, downloads
# ══════════════════════════════════════════════════════════════════

# Rate limits for landing analytics
PAGE_VIEW_RATE_LIMIT = 30    # max page_view events per IP per hour
DOWNLOAD_RATE_LIMIT = 10     # max download_track events per IP per hour


class LandingAnalytics:
    """Privacy-respecting analytics for the landing page.

    Tracked metrics:
      - Page views (total + daily)
      - Unique daily visitors (hashed IP → daily set, no PII stored)
      - Referrer distribution (domain only, not full URL)
      - Language distribution (user-selected lang on landing)
      - Screen size distribution (bucketed: mobile / tablet / desktop)
      - Downloads per asset (windows / linux)
      - Download sources (direct / landing-button / github)

    Privacy:
      - IPs are hashed with daily rotating salt (SHA-256)
      - No cookies, no persistent user IDs
      - Referrers are stripped to domain only
      - Screen sizes are bucketed, not exact
    """

    def __init__(self, data_dir: Path):
        self._writer = JSONLWriter("landing", data_dir)
        self._start_time = time.monotonic()

        # ── Page view counters ────────────────────────────────
        self._total_views = 0
        self._daily_views: dict[str, int] = defaultdict(int)

        # ── Unique visitors (hashed IP per day) ───────────────
        self._daily_visitors: dict[str, set] = defaultdict(set)
        self._daily_salt = os.urandom(32)  # rotated daily
        self._salt_day = _day_key()

        # ── Distributions ─────────────────────────────────────
        self._referrers: dict[str, int] = defaultdict(int)
        self._languages: dict[str, int] = defaultdict(int)
        self._screen_sizes: dict[str, int] = defaultdict(int)

        # ── Download counters ─────────────────────────────────
        self._downloads_total = 0
        self._downloads_by_asset: dict[str, int] = defaultdict(int)
        self._downloads_by_source: dict[str, int] = defaultdict(int)
        self._daily_downloads: dict[str, int] = defaultdict(int)

        # ── Restore from disk ─────────────────────────────────
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        """Restore landing counters from the last JSONL snapshot.

        Restores: total views, downloads, daily breakdowns,
        referrers, languages, screen sizes, download distributions.
        Note: unique visitors (hashed IP sets) cannot be restored
        from counts — only the daily count is preserved.
        """
        try:
            records = self._writer.read_recent(max_lines=1)
            if not records:
                log.info("Landing: no previous data — starting fresh")
                return
            last = records[-1]

            # Restore totals
            self._total_views = int(last.get("total_views", 0))
            self._downloads_total = int(last.get("downloads_total", 0))

            # Restore daily breakdowns
            for day, count in last.get("daily_views", {}).items():
                self._daily_views[day] = int(count)
            for day, count in last.get("daily_downloads", {}).items():
                self._daily_downloads[day] = int(count)

            # Restore distributions
            for k, v in last.get("referrers", {}).items():
                self._referrers[k] = int(v)
            for k, v in last.get("languages", {}).items():
                self._languages[k] = int(v)
            for k, v in last.get("screen_sizes", {}).items():
                self._screen_sizes[k] = int(v)

            # Restore download distributions from flush data
            # (downloads_by_asset / downloads_by_source are saved
            #  starting from the next flush after this code deploys)
            for k, v in last.get("downloads_by_asset", {}).items():
                self._downloads_by_asset[k] = int(v)
            for k, v in last.get("downloads_by_source", {}).items():
                self._downloads_by_source[k] = int(v)

            log.info(
                "Landing: restored — %d views, %d downloads",
                self._total_views, self._downloads_total,
            )
        except Exception as exc:
            log.warning("Landing: failed to restore from disk: %s", exc)

    def _rotate_salt_if_needed(self) -> None:
        """Rotate the hashing salt daily for privacy."""
        today = _day_key()
        if today != self._salt_day:
            self._daily_salt = os.urandom(32)
            self._salt_day = today

    def _hash_ip(self, ip: str) -> str:
        """Hash IP with daily salt — not reversible, not linkable across days."""
        self._rotate_salt_if_needed()
        return hashlib.sha256(
            self._daily_salt + ip.encode()
        ).hexdigest()[:16]

    def _extract_domain(self, referrer: str) -> str:
        """Extract domain from referrer URL for privacy."""
        if not referrer:
            return "direct"
        ref = _sanitize_str(referrer, 500)
        try:
            from urllib.parse import urlparse
            parsed = urlparse(ref)
            domain = parsed.netloc or parsed.path.split("/")[0]
            # Strip www. prefix
            if domain.startswith("www."):
                domain = domain[4:]
            return domain[:100] if domain else "direct"
        except Exception:
            return "unknown"

    @staticmethod
    def _screen_bucket(width: int) -> str:
        """Bucket screen width for privacy."""
        if width <= 0:
            return "unknown"
        elif width < 768:
            return "mobile"
        elif width < 1024:
            return "tablet"
        elif width < 1440:
            return "desktop"
        else:
            return "desktop-large"

    def record_page_view(self, ip: str, referrer: str = "",
                         lang: str = "", screen_w: int = 0) -> None:
        """Record a landing page view."""
        today = _day_key()

        self._total_views += 1
        self._daily_views[today] += 1

        # Unique visitor tracking (hashed IP)
        hashed = self._hash_ip(ip)
        self._daily_visitors[today].add(hashed)

        # Distributions
        domain = self._extract_domain(referrer)
        _safe_incr(self._referrers, domain)

        if lang:
            safe_lang = _sanitize_str(lang, 10).lower()
            _safe_incr(self._languages, safe_lang)

        if screen_w > 0:
            bucket = self._screen_bucket(screen_w)
            _safe_incr(self._screen_sizes, bucket)

    def record_download(self, ip: str, asset: str = "windows",
                        source: str = "landing") -> None:
        """Record a download event."""
        today = _day_key()

        self._downloads_total += 1
        self._daily_downloads[today] += 1

        safe_asset = _sanitize_str(asset, 20).lower()
        safe_source = _sanitize_str(source, 20).lower()

        _safe_incr(self._downloads_by_asset, safe_asset)
        _safe_incr(self._downloads_by_source, safe_source)

    def get_summary(self) -> dict:
        """Return landing analytics summary."""
        today = _day_key()

        # Calculate unique visitors for today and last 7 days
        unique_today = len(self._daily_visitors.get(today, set()))
        unique_7d = sum(
            len(visitors)
            for day, visitors in self._daily_visitors.items()
        )

        # Views for last 7 days
        views_7d = sum(self._daily_views.values())

        # Daily breakdown (last 7 days)
        sorted_days = sorted(self._daily_views.keys())[-7:]
        daily = {}
        for day in sorted_days:
            daily[day] = {
                "views": self._daily_views.get(day, 0),
                "unique": len(self._daily_visitors.get(day, set())),
                "downloads": self._daily_downloads.get(day, 0),
            }

        return {
            "total_views": self._total_views,
            "views_today": self._daily_views.get(today, 0),
            "views_7d": views_7d,
            "unique_today": unique_today,
            "unique_7d": unique_7d,
            "downloads_total": self._downloads_total,
            "downloads_today": self._daily_downloads.get(today, 0),
            "daily": daily,
            "distributions": {
                "referrers": dict(
                    sorted(self._referrers.items(),
                           key=lambda x: x[1], reverse=True)[:20]
                ),
                "languages": dict(self._languages),
                "screen_sizes": dict(self._screen_sizes),
                "downloads_by_asset": dict(self._downloads_by_asset),
                "downloads_by_source": dict(self._downloads_by_source),
            },
        }

    def flush(self) -> None:
        """Flush current landing stats to JSONL.

        Includes all data needed to fully restore state after restart.
        """
        record = {
            "ts": _now_iso(),
            "day": _day_key(),
            "total_views": self._total_views,
            "downloads_total": self._downloads_total,
            "daily_views": dict(self._daily_views),
            "daily_downloads": dict(self._daily_downloads),
            "daily_unique": {
                day: len(visitors)
                for day, visitors in self._daily_visitors.items()
            },
            "referrers": dict(self._referrers),
            "languages": dict(self._languages),
            "screen_sizes": dict(self._screen_sizes),
            "downloads_by_asset": dict(self._downloads_by_asset),
            "downloads_by_source": dict(self._downloads_by_source),
        }
        self._writer.append(record)
        self._purge_old_days()

    def _purge_old_days(self) -> None:
        """Keep only last 30 days of daily data in memory."""
        cutoff = 30
        for store in (self._daily_views, self._daily_visitors,
                      self._daily_downloads):
            keys = sorted(store.keys())
            if len(keys) > cutoff:
                for k in keys[:-cutoff]:
                    del store[k]


# ══════════════════════════════════════════════════════════════════
#  Telegram alerting (server-critical only)
# ══════════════════════════════════════════════════════════════════

def send_telegram_alert(message: str) -> bool:
    """Send a critical alert to Telegram. Returns True on success."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    try:
        import urllib.request
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = json.dumps({
            "chat_id": TELEGRAM_CHAT_ID,
            "text": f"🚨 SecureShare Relay\n{message}",
            "parse_mode": "HTML",
        }).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as exc:
        log.error("Telegram alert failed: %s", exc)
        return False


# ══════════════════════════════════════════════════════════════════
#  Admin API key verification
# ══════════════════════════════════════════════════════════════════

def verify_admin_key(provided: str) -> bool:
    """Timing-safe comparison of the admin API key."""
    if not ADMIN_KEY:
        log.warning("RELAY_ADMIN_KEY not configured — admin API disabled")
        return False
    if not provided:
        return False
    return hmac.compare_digest(provided.encode(), ADMIN_KEY.encode())
