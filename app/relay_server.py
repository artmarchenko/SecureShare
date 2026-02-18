"""
SecureShare — Local WebSocket relay server.

Runs on localhost on a random free port.
Two WebSocket clients connect using the same session code as their
first message; the server then pipes all subsequent binary frames
between them bidirectionally.

Cloudflare Tunnel exposes this server to the internet so the remote
peer can connect without port forwarding.

The server never reads the content of the messages — it only forwards
raw bytes.  All data is E2E encrypted at the application layer.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Optional

log = logging.getLogger(__name__)

try:
    import websockets
    import websockets.server as _ws_server
    _HAS_WEBSOCKETS = True
except ImportError:
    _HAS_WEBSOCKETS = False


def _is_closed(ws) -> bool:
    """Compatible closed-check for websockets 10–14+."""
    # websockets ≥14 asyncio API: close_code is set when closed
    if hasattr(ws, "close_code"):
        return ws.close_code is not None
    # Legacy API (websockets <13): .closed property
    return getattr(ws, "closed", False)


class LocalRelayServer:
    """
    Asyncio WebSocket relay: pairs two peers by session code and
    bidirectionally proxies all messages between them.

    Usage (in a background thread automatically):
        server = LocalRelayServer()
        ok = server.start()          # starts asyncio loop in a thread
        port = server.port           # random free port
        server.stop()
    """

    def __init__(self):
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._server = None
        self._port: int = 0
        self._ready = threading.Event()
        # session_code → [ws_a, ws_b]  (protected by asyncio, single-threaded)
        self._sessions: dict[str, list] = {}

    # ── Public API ─────────────────────────────────────────────────

    @property
    def port(self) -> int:
        return self._port

    def start(self) -> bool:
        """Start the server.  Returns True when ready to accept connections."""
        if not _HAS_WEBSOCKETS:
            log.error("websockets package not installed — relay server unavailable")
            return False
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="relay-server"
        )
        self._thread.start()
        return self._ready.wait(timeout=10)

    def stop(self) -> None:
        if self._loop and self._server:
            self._loop.call_soon_threadsafe(self._server.close)

    # ── Internal ───────────────────────────────────────────────────

    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve())
        except Exception as exc:
            log.error("Relay server crashed: %s", exc)
        finally:
            self._ready.set()   # unblock start() if it was waiting

    async def _serve(self) -> None:
        # port=0 → OS picks a free port
        async with websockets.serve(self._handler, "localhost", 0) as server:
            self._server = server
            sock = server.sockets[0]
            self._port = sock.getsockname()[1]
            log.info("Local relay server listening on port %d", self._port)
            self._ready.set()
            await server.wait_closed()

    async def _handler(self, websocket) -> None:
        """
        Protocol:
          1. Client sends session code (text frame).
          2. Server waits until a second client sends the same code.
          3. Server proxies all subsequent binary (and text) frames
             from each client to the other.
        """
        # ── Step 1: read session code ──────────────────────────────
        try:
            code = await asyncio.wait_for(websocket.recv(), timeout=15.0)
        except Exception:
            return

        if not isinstance(code, str):
            code = code.decode("utf-8", errors="replace")

        # ── Step 2: register and wait for peer ─────────────────────
        if code not in self._sessions:
            self._sessions[code] = []
        self._sessions[code].append(websocket)
        peers = self._sessions[code]

        loop = asyncio.get_event_loop()
        deadline = loop.time() + 300.0   # wait up to 5 min for peer

        while len(peers) < 2:
            if loop.time() > deadline:
                log.debug("Relay: peer never arrived for code %s…", code[:4])
                self._cleanup(code, websocket)
                return
            if _is_closed(websocket):
                self._cleanup(code, websocket)
                return
            await asyncio.sleep(0.05)

        peer = next((ws for ws in peers if ws is not websocket), None)
        if peer is None:
            self._cleanup(code, websocket)
            return

        log.debug("Relay: both peers connected for code %s…", code[:4])

        # ── Step 3: pipe ───────────────────────────────────────────
        try:
            async for message in websocket:
                if _is_closed(peer):
                    break
                try:
                    await peer.send(message)
                except Exception:
                    break
        except Exception:
            pass
        finally:
            self._cleanup(code, websocket)

    def _cleanup(self, code: str, websocket) -> None:
        if code in self._sessions:
            try:
                self._sessions[code].remove(websocket)
            except ValueError:
                pass
            if not self._sessions[code]:
                del self._sessions[code]
