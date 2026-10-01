"""Run the repository's relay server in-process on loopback for tests."""

from __future__ import annotations

import asyncio
import importlib
import os
import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVER_DIR = ROOT / "server"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def load_server_modules(data_dir: Path):
    """Import server/relay_server.py with test-friendly environment."""
    os.environ.update({
        "RELAY_DATA_DIR": str(data_dir),
        "RELAY_ADMIN_KEY": "test-admin-key",
        "RELAY_RATE_LIMIT": "100000",
        "RELAY_MAX_CONN_PER_IP": "1000",
        "RELAY_TRUSTED_PROXIES": "",
    })
    if str(SERVER_DIR) not in sys.path:
        sys.path.insert(0, str(SERVER_DIR))
    analytics = importlib.import_module("analytics")
    relay = importlib.import_module("relay_server")
    return relay, analytics


class LocalRelay:
    def __init__(self, data_dir: Path, host: str = "127.0.0.1", port: int = 0) -> None:
        self.relay_mod, self.analytics_mod = load_server_modules(data_dir)
        self.ws_port = port or _free_port()
        self.http_port = _free_port()
        self.relay_mod.LISTEN_HOST = host
        self.relay_mod.LISTEN_PORT = self.ws_port
        self.relay_mod.HEALTH_PORT = self.http_port

        self.server = self.relay_mod.RelayServer()
        self._loop = asyncio.new_event_loop()
        self._task: asyncio.Task | None = None
        self._thread = threading.Thread(target=self._run, name="local-relay", daemon=True)
        self._thread.start()
        self._wait_ready()

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.ws_port}"

    @property
    def http_url(self) -> str:
        return f"http://127.0.0.1:{self.http_port}"

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._task = self._loop.create_task(self.server.start())
        try:
            self._loop.run_until_complete(self._task)
        except (asyncio.CancelledError, Exception):
            pass

    def _wait_ready(self, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.ws_port), timeout=0.2):
                    pass
                with socket.create_connection(("127.0.0.1", self.http_port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("local relay did not start")

    def active_rooms(self) -> int:
        return len(self.server._rooms)

    def drop_all_connections(self) -> int:
        """Abruptly close every client socket (simulates a network outage)."""
        async def _drop() -> int:
            count = 0
            for room in list(self.server._rooms.values()):
                for ws in list(room):
                    transport = getattr(ws, "transport", None)
                    if transport is not None:
                        transport.abort()
                        count += 1
            return count
        return asyncio.run_coroutine_threadsafe(_drop(), self._loop).result(5)

    def close(self) -> None:
        def _cancel_all() -> None:
            for task in asyncio.all_tasks(self._loop):
                task.cancel()
        self._loop.call_soon_threadsafe(_cancel_all)
        self._thread.join(timeout=10)
