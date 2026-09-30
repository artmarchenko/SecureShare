"""
Shared test configuration.

Isolation guarantees for every test run:
  * APPDATA points to a throw-away directory, so tests never touch the
    developer's real settings (language, update cooldown, telemetry opt-in).
  * A network guard refuses any connection that is not loopback, so no test
    can reach the production relay, GitHub or the telemetry endpoint by
    accident. Tests marked ``live`` are exempt and only run with --run-live.
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Must happen before any `app.*` import: several modules compute their
# settings paths from APPDATA at import time.
_APPDATA = Path(tempfile.mkdtemp(prefix="secureshare-tests-appdata-"))
os.environ["APPDATA"] = str(_APPDATA)

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ── Markers by directory ────────────────────────────────────────────

_DIR_MARKERS = {
    "unit": "unit",
    "server": "server",
    "integration": "integration",
    "adversarial": "adversarial",
    "ui": "ui",
    "live": "live",
}


def pytest_addoption(parser):
    parser.addoption("--run-live", action="store_true",
                     help="run tests marked 'live' (talk to the production relay)")


def pytest_collection_modifyitems(config, items):
    run_live = config.getoption("--run-live")
    skip_live = pytest.mark.skip(reason="live test: pass --run-live to run")
    for item in items:
        rel = Path(str(item.fspath)).resolve().relative_to(ROOT / "tests")
        marker = _DIR_MARKERS.get(rel.parts[0]) if len(rel.parts) > 1 else None
        if marker:
            item.add_marker(getattr(pytest.mark, marker))
        if "live" in item.keywords and not run_live:
            item.add_marker(skip_live)


# ── Network guard ───────────────────────────────────────────────────

_LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost", "0.0.0.0", ""}


class NetworkAccessBlocked(RuntimeError):
    pass


def _host_of(address) -> str:
    if isinstance(address, tuple) and address:
        return str(address[0])
    return str(address)


@pytest.fixture(autouse=True)
def _network_guard(request, monkeypatch):
    if "live" in request.keywords:
        yield
        return

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo

    def _check(address):
        host = _host_of(address)
        if host not in _LOCAL_HOSTS:
            raise NetworkAccessBlocked(f"test tried to reach non-local host {host!r}")

    def guarded_connect(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            _check(address)
        return real_connect(self, address)

    def guarded_connect_ex(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            _check(address)
        return real_connect_ex(self, address)

    def guarded_getaddrinfo(host, *args, **kwargs):
        if host is not None and str(host) not in _LOCAL_HOSTS:
            raise NetworkAccessBlocked(f"test tried to resolve non-local host {host!r}")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    yield


# ── Telemetry sink ──────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def telemetry_sink(monkeypatch):
    """Capture anything the client would send to /api/crash or /api/telemetry."""
    sent: list[tuple[str, dict]] = []
    import app.telemetry as telemetry
    monkeypatch.setattr(telemetry, "_send_async", lambda url, data: sent.append((url, data)))
    return sent


# ── Local relay (real server code on loopback) ─────────────────────

@pytest.fixture(scope="session")
def local_relay(tmp_path_factory):
    from tests.helpers.local_relay import LocalRelay
    relay = LocalRelay(tmp_path_factory.mktemp("relay-data"))
    yield relay
    relay.close()


@pytest.fixture
def relay(local_relay, monkeypatch):
    """Point the client at the local relay and make reconnects fast."""
    from app import ws_relay
    monkeypatch.setattr(ws_relay, "VPS_RELAY_URL", local_relay.url)
    monkeypatch.setattr(ws_relay, "RECONNECT_BASE_DELAY", 0.1)
    monkeypatch.setattr(ws_relay, "RECONNECT_MAX_DELAY", 0.5)
    return local_relay


# ── Misc helpers ────────────────────────────────────────────────────

@pytest.fixture
def appdata() -> Path:
    return _APPDATA


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
