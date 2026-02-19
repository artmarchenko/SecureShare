"""
SecureShare Relay Server — production WebSocket relay.

Pairs two clients by session code and pipes raw bytes between them.
All data is E2E encrypted — the server never inspects content.

Security:
  - Rate limiting per real client IP (X-Forwarded-For aware)
  - Room timeout (auto-cleanup stale sessions)
  - Max 2 clients per room
  - Zero logging of session codes or payload
  - RAM only — no disk state
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import os
import time
from collections import defaultdict

import websockets
import websockets.server

# ── Configuration (env vars or defaults) ─────────────────────────────

LISTEN_HOST = os.getenv("RELAY_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("RELAY_PORT", "8765"))

# Security limits
MAX_CONNECTIONS_PER_IP = int(os.getenv("RELAY_MAX_CONN_PER_IP", "50"))
RATE_LIMIT_WINDOW = 60              # seconds
RATE_LIMIT_MAX = int(os.getenv("RELAY_RATE_LIMIT", "200"))  # connects per IP per window
ROOM_TIMEOUT = int(os.getenv("RELAY_ROOM_TIMEOUT", "1800"))  # 30 min
PEER_WAIT_TIMEOUT = 300             # 5 min waiting for second peer
HANDSHAKE_TIMEOUT = 15              # seconds to send session code

# Trusted proxy subnets (Docker internal networks)
TRUSTED_PROXIES = os.getenv("RELAY_TRUSTED_PROXIES", "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16")

# Logging — no sensitive data
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


# ── Relay Server ─────────────────────────────────────────────────────

class RelayServer:
    def __init__(self):
        self._rooms: dict[str, list] = {}
        self._room_created: dict[str, float] = {}
        self._rate_limiter = RateLimiter()
        self._stats = {"total_connections": 0, "total_rooms": 0, "active_rooms": 0}

    async def start(self) -> None:
        log.info("SecureShare Relay Server starting on %s:%d", LISTEN_HOST, LISTEN_PORT)
        asyncio.create_task(self._cleanup_loop())
        asyncio.create_task(self._stats_loop())

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
            # websockets 13+: ws.request.headers
            req = getattr(ws, "request", None)
            if req and hasattr(req, "headers"):
                xff = req.headers.get("X-Forwarded-For", "")
                if xff:
                    return xff.split(",")[0].strip()
            # websockets <13: ws.request_headers
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

        # Only trust XFF header if the direct connection is from a trusted proxy (e.g. Caddy)
        if direct_ip and self._is_trusted_proxy(direct_ip):
            xff_ip = self._get_xff_header(ws)
            if xff_ip:
                return xff_ip

        # Direct connection or untrusted proxy — use direct IP
        return direct_ip or "unknown"

    async def _handler(self, ws) -> None:
        """Handle a single WebSocket connection."""
        ip = self._get_client_ip(ws)

        # Rate limiting
        if not self._rate_limiter.check(ip):
            log.warning("Rate limit exceeded for %s", ip)
            await ws.close(4029, "rate limit exceeded")
            return

        self._rate_limiter.connect(ip)
        self._stats["total_connections"] += 1
        room_id = None

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

            # Hash the session code — don't store original in memory
            room_id = hashlib.sha256(code.encode()).hexdigest()[:32]

            # ── Step 2: join room ────────────────────────────────────
            if room_id not in self._rooms:
                self._rooms[room_id] = []
                self._room_created[room_id] = time.monotonic()
                self._stats["total_rooms"] += 1
                self._stats["active_rooms"] += 1

            room = self._rooms[room_id]

            # Clean dead connections from room (in-place to keep reference)
            dead = [w for w in room if self._is_closed(w)]
            for w in dead:
                room.remove(w)

            if len(room) >= 2:
                log.warning("Room full [%.8s…], rejecting %s", room_id, ip)
                await ws.close(4001, "room full")
                return

            room.append(ws)
            log.info("Peer joined room [%.8s…] (%d/2) from %s", room_id, len(room), ip)

            # ── Step 3: wait for peer ────────────────────────────────
            loop = asyncio.get_event_loop()
            deadline = loop.time() + PEER_WAIT_TIMEOUT

            while len(room) < 2:
                if loop.time() > deadline:
                    log.info("Peer wait timeout for room [%.8s…]", room_id)
                    return
                if self._is_closed(ws):
                    return
                await asyncio.sleep(0.1)

            peer = next((w for w in room if w is not ws), None)
            if peer is None or self._is_closed(peer):
                return

            log.info("Room [%.8s…] paired — relaying", room_id)

            # ── Step 4: relay ────────────────────────────────────────
            msg_count = 0
            try:
                async for message in ws:
                    msg_count += 1
                    if self._is_closed(peer):
                        break
                    try:
                        await peer.send(message)
                    except Exception:
                        break
            except Exception:
                pass

        finally:
            self._rate_limiter.disconnect(ip)
            if room_id:
                self._cleanup_room(room_id, ws)

    def _is_closed(self, ws) -> bool:
        if hasattr(ws, "close_code"):
            return ws.close_code is not None
        return getattr(ws, "closed", False)

    def _cleanup_room(self, room_id: str, ws) -> None:
        if room_id in self._rooms:
            try:
                self._rooms[room_id].remove(ws)
            except ValueError:
                pass
            if not self._rooms[room_id]:
                del self._rooms[room_id]
                self._room_created.pop(room_id, None)
                self._stats["active_rooms"] = max(0, self._stats["active_rooms"] - 1)
                log.info("Room [%.8s…] closed", room_id)

    async def _cleanup_loop(self) -> None:
        """Periodically remove stale rooms and clean rate limiter memory."""
        while True:
            await asyncio.sleep(60)
            # Clean rate limiter memory
            cleaned_ips = self._rate_limiter.cleanup()
            if cleaned_ips:
                log.debug("Rate limiter: cleaned %d stale IPs", cleaned_ips)
            now = time.monotonic()
            stale = [
                rid for rid, created in self._room_created.items()
                if now - created > ROOM_TIMEOUT
            ]
            for rid in stale:
                if rid in self._rooms:
                    room = self._rooms[rid]
                    # Close all connections in the room
                    for ws in list(room):  # iterate over copy
                        try:
                            await ws.close(4002, "room timeout")
                        except Exception:
                            pass
                    # In-place clear to keep reference integrity
                    room.clear()
                    # Now safe to remove the empty room
                    del self._rooms[rid]
                    self._room_created.pop(rid, None)
                    self._stats["active_rooms"] = max(0, self._stats["active_rooms"] - 1)
                    log.info("Stale room [%.8s…] cleaned up", rid)

    async def _stats_loop(self) -> None:
        """Log stats every 5 minutes."""
        while True:
            await asyncio.sleep(300)
            log.info("Stats: %s", self._stats)


# ── Entry point ──────────────────────────────────────────────────────

def main():
    server = RelayServer()
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        log.info("Shutting down...")

if __name__ == "__main__":
    main()
