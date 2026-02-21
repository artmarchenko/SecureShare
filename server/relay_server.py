"""
SecureShare Relay Server — production WebSocket relay.

Pairs two clients by session code and pipes raw bytes between them.
All data is E2E encrypted — the server never inspects content.

Security:
  - Rate limiting per real client IP (X-Forwarded-For from trusted proxies only)
  - Per-session data volume limit (default 5 GB)
  - Room timeout (auto-cleanup stale sessions)
  - Max 2 clients per room
  - Zero logging of session codes or payload
  - RAM only — no disk state for relay
  - Graceful shutdown (SIGTERM/SIGINT)

Analytics (v3.3):
  - Anonymous usage statistics (sessions, bytes, OS, versions)
  - Crash report collection (POST /api/crash)
  - Client telemetry events (POST /api/telemetry)
  - Admin API (GET /api/stats, /api/crashes) — key-protected
  - JSONL persistence + in-memory aggregation
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import signal
import time
import urllib.parse
from collections import defaultdict

import websockets
import websockets.server

from analytics import (
    StatsCollector,
    CrashStore,
    APIRateLimiter,
    verify_admin_key,
    send_telegram_alert,
    DATA_DIR,
    CRASH_RATE_LIMIT,
    TELEMETRY_RATE_LIMIT,
    MAX_CRASH_BODY,
    MAX_TELEMETRY_BODY,
)

# ── Configuration (env vars or defaults) ─────────────────────────────

LISTEN_HOST = os.getenv("RELAY_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("RELAY_PORT", "8765"))
HEALTH_PORT = int(os.getenv("RELAY_HEALTH_PORT", "8766"))

# Version info for /api/version (update on each release)
LATEST_CLIENT_VERSION = os.getenv("RELAY_LATEST_VERSION", "3.3.2")
DOWNLOAD_BASE_URL = os.getenv(
    "RELAY_DOWNLOAD_URL",
    "https://secureshare-relay.duckdns.org/download",
)
GITHUB_RELEASE_URL = os.getenv(
    "RELAY_GITHUB_URL",
    "https://github.com/artmarchenko/SecureShare/releases/latest",
)

# Security limits
MAX_CONNECTIONS_PER_IP = int(os.getenv("RELAY_MAX_CONN_PER_IP", "50"))
RATE_LIMIT_WINDOW = 60              # seconds
RATE_LIMIT_MAX = int(os.getenv("RELAY_RATE_LIMIT", "200"))  # connects per IP per window
ROOM_TIMEOUT = int(os.getenv("RELAY_ROOM_TIMEOUT", "1800"))  # 30 min
PEER_WAIT_TIMEOUT = 300             # 5 min waiting for second peer
HANDSHAKE_TIMEOUT = 15              # seconds to send session code
MAX_SESSION_BYTES = int(os.getenv(
    "RELAY_MAX_SESSION_BYTES", str(5 * 1024 * 1024 * 1024)
))  # 5 GB per session
BACKPRESSURE_HIGH = int(os.getenv("RELAY_BP_HIGH", str(4 * 1024 * 1024)))  # 4 MB — pause reading
BACKPRESSURE_LOW = int(os.getenv("RELAY_BP_LOW", str(1 * 1024 * 1024)))    # 1 MB — resume reading
BACKPRESSURE_TIMEOUT = 30  # seconds to wait before giving up

# Trusted proxy subnets (Docker internal networks)
TRUSTED_PROXIES = os.getenv("RELAY_TRUSTED_PROXIES", "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16")

# Logging — no sensitive data
LOG_FORMAT = os.getenv("RELAY_LOG_FORMAT", "text")  # "text" or "json"

if LOG_FORMAT == "json":
    import json as _json

    class _JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            entry = {
                "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
                "level": record.levelname,
                "msg": record.getMessage(),
            }
            if record.exc_info and record.exc_info[0]:
                entry["exc"] = self.formatException(record.exc_info)
            return _json.dumps(entry, ensure_ascii=False)

    _handler = logging.StreamHandler()
    _handler.setFormatter(_JsonFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[_handler])
else:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

log = logging.getLogger("relay")


# ── Rate limiter ─────────────────────────────────────────────────────

class RateLimiter:
    """Sliding-window rate limiter per IP with periodic memory cleanup."""

    def __init__(self):
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._connections: dict[str, int] = defaultdict(int)

    def check(self, ip: str) -> bool:
        """Return True if the connection is allowed."""
        now = time.monotonic()
        # Clean old entries for this IP
        self._attempts[ip] = [t for t in self._attempts[ip] if now - t < RATE_LIMIT_WINDOW]
        # Check rate
        if len(self._attempts[ip]) >= RATE_LIMIT_MAX:
            return False
        # Check concurrent connections
        if self._connections[ip] >= MAX_CONNECTIONS_PER_IP:
            return False
        self._attempts[ip].append(now)
        return True

    def connect(self, ip: str) -> None:
        self._connections[ip] = self._connections.get(ip, 0) + 1

    def disconnect(self, ip: str) -> None:
        self._connections[ip] = max(0, self._connections.get(ip, 1) - 1)
        if self._connections[ip] == 0:
            self._connections.pop(ip, None)

    def cleanup(self) -> int:
        """Remove stale IPs with no recent attempts and no active connections.
        Returns number of IPs cleaned."""
        now = time.monotonic()
        stale_ips = []
        for ip, timestamps in list(self._attempts.items()):
            # Remove expired timestamps
            fresh = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
            if not fresh and self._connections.get(ip, 0) == 0:
                stale_ips.append(ip)
            else:
                self._attempts[ip] = fresh
        for ip in stale_ips:
            del self._attempts[ip]
        return len(stale_ips)


# ── HTTP API Router ──────────────────────────────────────────────────

class HTTPRouter:
    """Minimal async HTTP router for the health/API port.

    Handles:
      GET  /health               — health check (public)
      POST /api/crash            — crash report (rate-limited)
      POST /api/telemetry        — telemetry event (rate-limited)
      GET  /api/stats?key=...    — full stats (admin)
      GET  /api/crashes?key=...  — grouped crashes (admin)
      GET  /api/logs?key=...&file=...  — download JSONL (admin)
      GET  /api/files?key=...    — list log files (admin)
    """

    def __init__(self, stats: StatsCollector, crashes: CrashStore):
        self._stats = stats
        self._crashes = crashes
        self._api_limiter = APIRateLimiter()

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle an HTTP connection on the health/API port."""
        try:
            # Read request (max 64 KB to prevent abuse)
            raw = await asyncio.wait_for(reader.read(65536), timeout=10)
            if not raw:
                return

            request_text = raw.decode("utf-8", errors="replace")
            method, path, query, headers, body = _parse_http(request_text)

            # Get client IP for rate limiting
            ip = _get_ip_from_headers(headers, writer)

            # Route
            if method == "GET" and path == "/health":
                await self._handle_health(writer)
            elif method == "GET" and path == "/api/version":
                await self._handle_version(writer)
            elif method == "POST" and path == "/api/crash":
                await self._handle_crash(writer, body, ip)
            elif method == "POST" and path == "/api/telemetry":
                await self._handle_telemetry(writer, body, ip)
            elif method == "GET" and path == "/api/stats":
                await self._handle_stats(writer, query, ip)
            elif method == "GET" and path == "/api/crashes":
                await self._handle_crashes(writer, query, ip)
            elif method == "GET" and path == "/api/files":
                await self._handle_files(writer, query, ip)
            elif method == "GET" and path == "/api/logs":
                await self._handle_logs(writer, query, ip)
            else:
                await _send_response(writer, 404,
                                     {"error": "not found"})
        except asyncio.TimeoutError:
            pass
        except Exception as exc:
            log.debug("HTTP handler error: %s", exc)
            try:
                await _send_response(writer, 500,
                                     {"error": "internal error"})
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── Handlers ───────────────────────────────────────────────

    async def _handle_health(self, writer) -> None:
        summary = self._stats.get_summary()
        body = {
            "status": "ok",
            "uptime_hours": summary["uptime_hours"],
            "active_rooms": summary["lifetime"]["sessions_created"]
            - summary["lifetime"]["sessions_completed"]
            - summary["lifetime"]["sessions_timeout"],
            "total_connections": summary["lifetime"]["connections_total"],
        }
        await _send_response(writer, 200, body)

    async def _handle_version(self, writer) -> None:
        """Public endpoint: latest version info for client update checks.

        No auth required — returns only public version metadata.
        Clients (including old versions via landing page) use this
        to discover new releases without hitting GitHub API limits.
        """
        body = {
            "latest_version": LATEST_CLIENT_VERSION,
            "download_url": DOWNLOAD_BASE_URL,
            "release_url": GITHUB_RELEASE_URL,
            "assets": {
                "windows": f"{DOWNLOAD_BASE_URL}/SecureShare.zip",
                "linux": f"{DOWNLOAD_BASE_URL}/SecureShare-linux-x64.tar.gz",
            },
        }
        await _send_response(writer, 200, body)

    async def _handle_crash(self, writer, body: str, ip: str) -> None:
        # Rate limit
        if not self._api_limiter.check(ip, CRASH_RATE_LIMIT):
            await _send_response(writer, 429,
                                 {"error": "rate limit exceeded"})
            return
        # Size limit
        if len(body) > MAX_CRASH_BODY:
            await _send_response(writer, 413,
                                 {"error": "body too large"})
            return
        # Parse JSON
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            await _send_response(writer, 400,
                                 {"error": "invalid JSON"})
            return
        if not isinstance(data, dict):
            await _send_response(writer, 400,
                                 {"error": "expected JSON object"})
            return

        ok = self._crashes.add(data)
        if ok:
            await _send_response(writer, 201,
                                 {"status": "received"})
        else:
            await _send_response(writer, 400,
                                 {"error": "invalid crash report"})

    async def _handle_telemetry(self, writer, body: str, ip: str) -> None:
        if not self._api_limiter.check(ip, TELEMETRY_RATE_LIMIT):
            await _send_response(writer, 429,
                                 {"error": "rate limit exceeded"})
            return
        if len(body) > MAX_TELEMETRY_BODY:
            await _send_response(writer, 413,
                                 {"error": "body too large"})
            return
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            await _send_response(writer, 400,
                                 {"error": "invalid JSON"})
            return
        if not isinstance(data, dict):
            await _send_response(writer, 400,
                                 {"error": "expected JSON object"})
            return

        self._stats.record_client_event(data)
        await _send_response(writer, 201, {"status": "received"})

    async def _handle_stats(self, writer, query: dict, ip: str) -> None:
        if not await self._check_admin(writer, query, ip):
            return
        summary = self._stats.get_summary()
        await _send_response(writer, 200, summary)

    async def _handle_crashes(self, writer, query: dict, ip: str) -> None:
        if not await self._check_admin(writer, query, ip):
            return
        try:
            hours = min(int(query.get("hours", "48")), 720)  # max 30 days
        except (ValueError, TypeError):
            hours = 48
        grouped = self._crashes.get_grouped(hours)
        await _send_response(writer, 200, grouped)

    async def _handle_files(self, writer, query: dict, ip: str) -> None:
        if not await self._check_admin(writer, query, ip):
            return
        files = {
            "stats_files": self._stats._writer.list_files(),
            "crash_files": self._crashes.list_files(),
        }
        await _send_response(writer, 200, files)

    async def _handle_logs(self, writer, query: dict, ip: str) -> None:
        if not await self._check_admin(writer, query, ip):
            return

        filename = query.get("file", "")
        if not filename:
            await _send_response(writer, 400,
                                 {"error": "missing 'file' parameter"})
            return

        # Try stats files first, then crash files
        path = self._stats._writer.get_file_path(filename)
        if path is None:
            path = self._crashes.get_file_path(filename)
        if path is None:
            await _send_response(writer, 404,
                                 {"error": "file not found"})
            return

        # Send raw file
        try:
            data = path.read_bytes()
            # Sanitize filename for Content-Disposition (prevent CRLF injection)
            safe_name = path.name.replace("\r", "").replace("\n", "")
            safe_name = safe_name.replace('"', "'")  # escape quotes
            response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/x-ndjson\r\n"
                f"Content-Length: {len(data)}\r\n"
                f"Content-Disposition: attachment; filename=\"{safe_name}\"\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            writer.write(response.encode() + data)
            await writer.drain()
        except Exception:
            await _send_response(writer, 500,
                                 {"error": "file read error"})

    # ── Auth helper ────────────────────────────────────────────

    async def _check_admin(self, writer, query: dict, ip: str) -> bool:
        """Verify admin API key. Sends error response if invalid.
        Returns True if authorized (caller should continue).
        Returns False if unauthorized (response already sent).
        """
        if self._api_limiter.is_admin_locked(ip):
            await _send_response(writer, 403,
                                 {"error": "too many failed attempts, locked"})
            return False

        key = query.get("key", "")
        if not verify_admin_key(key):
            self._api_limiter.record_admin_fail(ip)
            await _send_response(writer, 401,
                                 {"error": "unauthorized"})
            return False
        return True


# ── HTTP helpers ──────────────────────────────────────────────────

def _parse_http(raw: str) -> tuple[str, str, dict, dict, str]:
    """Parse a raw HTTP request into (method, path, query, headers, body)."""
    parts = raw.split("\r\n\r\n", 1)
    header_section = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    lines = header_section.split("\r\n")
    request_line = lines[0] if lines else ""
    tokens = request_line.split(" ")
    method = tokens[0].upper() if tokens else ""
    full_path = tokens[1] if len(tokens) > 1 else "/"

    # Parse path + query string
    parsed = urllib.parse.urlparse(full_path)
    path = parsed.path
    query = dict(urllib.parse.parse_qsl(parsed.query))

    # Parse headers
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    return method, path, query, headers, body


def _get_ip_from_headers(
    headers: dict[str, str], writer: asyncio.StreamWriter
) -> str:
    """Extract client IP from headers or transport.

    Priority:
      1. X-Real-IP — set by Caddy to the actual remote address
      2. X-Forwarded-For — LAST entry (Caddy appends real IP at the end)
      3. Transport peername — direct connection IP
    """
    # Prefer X-Real-IP (set explicitly by Caddy, cannot be spoofed)
    real_ip = headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip

    # Fallback: last entry in XFF (Caddy appends, so last = real IP)
    xff = headers.get("x-forwarded-for", "")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[-1]  # Last = added by Caddy = real IP

    try:
        peername = writer.get_extra_info("peername")
        if peername:
            return peername[0]
    except Exception:
        pass
    return "unknown"


async def _send_response(
    writer: asyncio.StreamWriter,
    status: int,
    body: dict | str,
) -> None:
    """Send an HTTP JSON response."""
    status_text = {
        200: "OK", 201: "Created", 400: "Bad Request",
        401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
        413: "Payload Too Large", 429: "Too Many Requests",
        500: "Internal Server Error",
    }.get(status, "Unknown")

    if isinstance(body, dict):
        body_bytes = json.dumps(body, ensure_ascii=False,
                                indent=2).encode("utf-8")
        content_type = "application/json"
    else:
        body_bytes = body.encode("utf-8")
        content_type = "text/plain"

    response = (
        f"HTTP/1.1 {status} {status_text}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: close\r\n"
        f"X-Content-Type-Options: nosniff\r\n"
        f"\r\n"
    )
    writer.write(response.encode() + body_bytes)
    await writer.drain()


# ── Relay Server ─────────────────────────────────────────────────────

class RelayServer:
    def __init__(self):
        self._rooms: dict[str, list] = {}
        self._room_created: dict[str, float] = {}
        self._room_events: dict[str, asyncio.Event] = {}  # signals when room is paired
        self._rate_limiter = RateLimiter()
        self._stats_basic = {"total_connections": 0, "total_rooms": 0, "active_rooms": 0}

        # Analytics
        self._analytics = StatsCollector(DATA_DIR)
        self._crashes = CrashStore(DATA_DIR)
        self._http_router = HTTPRouter(self._analytics, self._crashes)

    async def start(self) -> None:
        log.info("SecureShare Relay Server starting on %s:%d", LISTEN_HOST, LISTEN_PORT)
        asyncio.create_task(self._cleanup_loop())
        asyncio.create_task(self._stats_loop())
        asyncio.create_task(self._analytics_flush_loop())

        # HTTP API server (health + admin + crash/telemetry endpoints)
        api_server = await asyncio.start_server(
            self._http_router.handle, LISTEN_HOST, HEALTH_PORT,
        )
        log.info("HTTP API on :%d (/health, /api/*)", HEALTH_PORT)

        async with websockets.serve(
            self._handler,
            LISTEN_HOST,
            LISTEN_PORT,
            max_size=2 * 1024 * 1024,        # 2 MB max frame
            ping_interval=30,
            ping_timeout=120,
            close_timeout=10,
        ) as server:
            log.info("Relay server ready. Waiting for connections...")
            await server.wait_closed()

        api_server.close()

    def _is_trusted_proxy(self, ip: str) -> bool:
        """Check if the IP belongs to a trusted proxy network."""
        try:
            addr = ipaddress.ip_address(ip)
            for subnet_str in TRUSTED_PROXIES.split(","):
                subnet_str = subnet_str.strip()
                if subnet_str and addr in ipaddress.ip_network(subnet_str, strict=False):
                    return True
        except (ValueError, TypeError):
            pass
        return False

    def _get_xff_header(self, ws) -> str:
        """Extract X-Forwarded-For header from WebSocket request."""
        try:
            req = getattr(ws, "request", None)
            if req and hasattr(req, "headers"):
                xff = req.headers.get("X-Forwarded-For", "")
                if xff:
                    return xff.split(",")[0].strip()
            req_headers = getattr(ws, "request_headers", None)
            if req_headers:
                xff = req_headers.get("X-Forwarded-For", "")
                if xff:
                    return xff.split(",")[0].strip()
        except Exception:
            pass
        return ""

    def _get_client_ip(self, ws) -> str:
        """Get real client IP. Trust X-Forwarded-For ONLY from trusted proxies."""
        direct_ip = ""
        if ws.remote_address:
            direct_ip = ws.remote_address[0]

        if direct_ip and self._is_trusted_proxy(direct_ip):
            xff_ip = self._get_xff_header(ws)
            if xff_ip:
                return xff_ip

        return direct_ip or "unknown"

    async def _handler(self, ws) -> None:
        """Handle a single WebSocket connection."""
        ip = self._get_client_ip(ws)

        # Rate limiting
        if not self._rate_limiter.check(ip):
            log.warning("Rate limit exceeded for %s", ip)
            self._analytics.record_rate_limit()
            await ws.close(4029, "rate limit exceeded")
            return

        self._rate_limiter.connect(ip)
        self._stats_basic["total_connections"] += 1
        self._analytics.record_connection()
        room_id = None
        paired = False
        relay_start = None
        bytes_relayed = 0

        try:
            # ── Step 1: receive session code ─────────────────────────
            try:
                code = await asyncio.wait_for(ws.recv(), timeout=HANDSHAKE_TIMEOUT)
            except asyncio.TimeoutError:
                log.debug("Handshake timeout for %s", ip)
                return
            except Exception:
                return

            if not isinstance(code, str):
                code = code.decode("utf-8", errors="replace")

            room_id = hashlib.sha256(code.encode()).hexdigest()[:32]

            # ── Step 2: join room ────────────────────────────────────
            if room_id not in self._rooms:
                self._rooms[room_id] = []
                self._room_created[room_id] = time.monotonic()
                self._room_events[room_id] = asyncio.Event()
                self._stats_basic["total_rooms"] += 1
                self._stats_basic["active_rooms"] += 1
                self._analytics.record_session_created()

            room = self._rooms[room_id]

            dead = [w for w in room if self._is_closed(w)]
            for w in dead:
                room.remove(w)

            if len(room) >= 2:
                log.warning("Room full [%.8s…], rejecting %s", room_id, ip)
                await ws.close(4001, "room full")
                return

            room.append(ws)
            log.info("Peer joined room [%.8s…] (%d/2) from %s", room_id, len(room), ip)

            # Update peak rooms
            self._analytics.update_peak_rooms(self._stats_basic["active_rooms"])

            if len(room) == 2 and room_id in self._room_events:
                self._room_events[room_id].set()

            # ── Step 3: wait for peer ────────────────────────────────
            if len(room) < 2:
                event = self._room_events.get(room_id)
                if event is None:
                    return
                try:
                    await asyncio.wait_for(event.wait(), timeout=PEER_WAIT_TIMEOUT)
                except asyncio.TimeoutError:
                    log.info("Peer wait timeout for room [%.8s…]", room_id)
                    self._analytics.record_session_timeout()
                    return
                if self._is_closed(ws):
                    return

            peer = next((w for w in room if w is not ws), None)
            if peer is None or self._is_closed(peer):
                return

            paired = True
            self._analytics.record_session_paired()
            relay_start = time.monotonic()
            log.info("Room [%.8s…] paired — relaying", room_id)

            # ── Step 4: relay with backpressure ──────────────────────
            msg_count = 0
            try:
                async for message in ws:
                    msg_count += 1
                    msg_len = len(message) if isinstance(message, (bytes, bytearray)) else len(message.encode())
                    bytes_relayed += msg_len
                    if bytes_relayed > MAX_SESSION_BYTES:
                        log.warning("Session data limit exceeded for room [%.8s…]: %d bytes", room_id, bytes_relayed)
                        self._analytics.record_data_limit_exceeded()
                        await ws.close(4003, "session data limit exceeded")
                        break
                    if self._is_closed(peer):
                        break
                    try:
                        await peer.send(message)
                    except Exception:
                        break
                    transport = getattr(peer, "transport", None)
                    if transport is not None:
                        buf_size = transport.get_write_buffer_size()
                        if buf_size > BACKPRESSURE_HIGH:
                            self._analytics.record_backpressure()
                            try:
                                deadline = asyncio.get_event_loop().time() + BACKPRESSURE_TIMEOUT
                                while transport.get_write_buffer_size() > BACKPRESSURE_LOW:
                                    if asyncio.get_event_loop().time() > deadline:
                                        log.warning("Backpressure timeout for room [%.8s…]", room_id)
                                        break
                                    await asyncio.sleep(0.05)
                            except Exception:
                                break
            except Exception:
                pass

        finally:
            self._rate_limiter.disconnect(ip)

            # Record completed session stats
            if paired and relay_start is not None and bytes_relayed > 0:
                duration = time.monotonic() - relay_start
                self._analytics.record_session_completed(bytes_relayed, duration)

            if room_id:
                self._cleanup_room(room_id, ws)

    @staticmethod
    def _is_closed(ws) -> bool:
        """Check if WebSocket is closed. Works with websockets 12–16+."""
        close_code = getattr(ws, "close_code", None)
        if close_code is not None:
            return True
        if getattr(ws, "closed", False):
            return True
        state = getattr(ws, "state", None)
        if state is not None:
            return getattr(state, "value", -1) >= 2
        return False

    def _cleanup_room(self, room_id: str, ws) -> None:
        if room_id in self._rooms:
            try:
                self._rooms[room_id].remove(ws)
            except ValueError:
                pass
            if not self._rooms[room_id]:
                del self._rooms[room_id]
                self._room_created.pop(room_id, None)
                self._room_events.pop(room_id, None)
                self._stats_basic["active_rooms"] = max(0, self._stats_basic["active_rooms"] - 1)
                log.info("Room [%.8s…] closed", room_id)

    async def _cleanup_loop(self) -> None:
        """Periodically remove stale rooms and clean rate limiter memory."""
        while True:
            try:
                await asyncio.sleep(60)
                cleaned_ips = self._rate_limiter.cleanup()
                if cleaned_ips:
                    log.debug("Rate limiter: cleaned %d stale IPs", cleaned_ips)
                self._http_router._api_limiter.cleanup()
                now = time.monotonic()
                stale = [
                    rid for rid, created in self._room_created.items()
                    if now - created > ROOM_TIMEOUT
                ]
                for rid in stale:
                    if rid in self._rooms:
                        room = self._rooms[rid]
                        for ws in list(room):
                            try:
                                await ws.close(4002, "room timeout")
                            except Exception:
                                pass
                        room.clear()
                        del self._rooms[rid]
                        self._room_created.pop(rid, None)
                        self._room_events.pop(rid, None)
                        self._stats_basic["active_rooms"] = max(0, self._stats_basic["active_rooms"] - 1)
                        self._analytics.record_session_timeout()
                        log.info("Stale room [%.8s…] cleaned up", rid)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Error in cleanup loop")

    async def _stats_loop(self) -> None:
        """Log stats every 5 minutes."""
        while True:
            try:
                await asyncio.sleep(300)
                self._analytics.update_peak_rooms(self._stats_basic["active_rooms"])
                log.info("Stats: %s", self._stats_basic)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Error in stats loop")

    async def _analytics_flush_loop(self) -> None:
        """Flush analytics to disk every hour."""
        while True:
            try:
                await asyncio.sleep(3600)
                self._analytics.flush_hourly()
                log.info("Analytics flushed to disk")
            except asyncio.CancelledError:
                # Flush before shutdown
                try:
                    self._analytics.flush_hourly()
                except Exception:
                    pass
                raise
            except Exception:
                log.exception("Error in analytics flush loop")


# ── Entry point ──────────────────────────────────────────────────────

def main():
    server = RelayServer()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Ensure data directory exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    shutdown_event = asyncio.Event()

    def _signal_handler():
        log.info("Shutdown signal received — closing all connections...")
        shutdown_event.set()
        send_telegram_alert("Server shutting down (SIGTERM/SIGINT)")

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            pass

    async def _run():
        server_task = asyncio.create_task(server.start())
        shutdown_task = asyncio.create_task(shutdown_event.wait())
        done, pending = await asyncio.wait(
            {server_task, shutdown_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        for rid, room in list(server._rooms.items()):
            for ws in list(room):
                try:
                    await ws.close(1001, "server shutting down")
                except Exception:
                    pass
        # Final analytics flush
        server._analytics.flush_hourly()
        log.info("Server stopped gracefully. Stats: %s", server._stats_basic)

    try:
        loop.run_until_complete(_run())
    except KeyboardInterrupt:
        log.info("Interrupted — shutting down...")
    finally:
        loop.close()


if __name__ == "__main__":
    main()
