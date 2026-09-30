"""Relay HTTP API (/health, /api/*) exercised over real loopback HTTP."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from tests.helpers.local_relay import LocalRelay

ADMIN = "test-admin-key"


@pytest.fixture
def srv(tmp_path_factory):
    relay = LocalRelay(tmp_path_factory.mktemp("relay-http"))
    yield relay
    relay.close()


def call(srv, path, method="GET", body: bytes | None = None, headers=None):
    req = urllib.request.Request(srv.http_url + path, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def as_json(raw: bytes):
    return json.loads(raw.decode("utf-8"))


# ── Public endpoints ────────────────────────────────────────────────

def test_health(srv):
    status, body = call(srv, "/health")
    data = as_json(body)
    assert status == 200
    assert data["status"] == "ok" and data["active_rooms"] == 0


def test_version_matches_client_config(srv):
    from app.config import APP_VERSION
    status, body = call(srv, "/api/version")
    assert status == 200
    assert as_json(body)["latest_version"] == APP_VERSION


def test_unknown_path_is_404(srv):
    assert call(srv, "/nope")[0] == 404
    assert call(srv, "/health", method="POST", body=b"")[0] == 404


def test_responses_have_nosniff_header(srv):
    with urllib.request.urlopen(srv.http_url + "/health", timeout=5) as resp:
        assert resp.headers["X-Content-Type-Options"] == "nosniff"


# ── Crash reports ───────────────────────────────────────────────────

def test_crash_report_accepted_and_sanitised(srv):
    report = {"error_type": "ValueError", "error_message": "bad\x00thing", "state": "s" * 500, "ram_mb": -5}
    status, _ = call(srv, "/api/crash", "POST", json.dumps(report).encode())
    assert status == 201
    stored = srv.server._crashes._recent[-1]
    assert stored["error_message"] == "badthing"
    assert len(stored["state"]) == 50
    assert stored["ram_mb"] == 0


@pytest.mark.parametrize("body,code", [
    (b"not json", 400),
    (b"[1, 2]", 400),
    (b"{}", 400),                                   # no useful fields
    (json.dumps({"error_type": "x" * 40000}).encode(), 413),
], ids=["invalid-json", "not-object", "empty", "too-large"])
def test_crash_report_rejected(srv, body, code):
    assert call(srv, "/api/crash", "POST", body)[0] == code


def test_crash_reports_are_rate_limited(srv):
    body = json.dumps({"error_type": "E"}).encode()
    codes = [call(srv, "/api/crash", "POST", body)[0] for _ in range(7)]
    assert codes[:5] == [201] * 5
    assert codes[5:] == [429, 429]


# ── Telemetry / landing analytics ───────────────────────────────────

def test_telemetry_event_updates_distributions(srv):
    event = {"app_version": "3.4.0", "os": "Windows-10", "outcome": "error", "error_type": "OSError"}
    assert call(srv, "/api/telemetry", "POST", json.dumps(event).encode())[0] == 201
    summary = srv.server._analytics.get_summary()
    assert summary["distributions"]["app_versions"]["3.4.0"] >= 1
    assert summary["distributions"]["error_types"]["client:OSError"] >= 1


def test_page_view_and_download_tracking(srv):
    view = {"referrer": "https://www.reddit.com/r/x", "lang": "EN", "screen_w": 400}
    assert call(srv, "/api/page_view", "POST", json.dumps(view).encode())[0] == 201
    assert call(srv, "/api/download_track", "POST", json.dumps({"asset": "linux"}).encode())[0] == 201
    landing = srv.server._landing.get_summary()
    assert landing["distributions"]["referrers"]["reddit.com"] == 1
    assert landing["distributions"]["languages"]["en"] == 1
    assert landing["distributions"]["screen_sizes"]["mobile"] == 1
    assert landing["distributions"]["downloads_by_asset"]["linux"] == 1


# ── Admin API ───────────────────────────────────────────────────────

def test_admin_requires_key(srv):
    assert call(srv, "/api/stats")[0] == 401
    assert call(srv, "/api/stats?key=wrong")[0] == 401
    status, body = call(srv, f"/api/stats?key={ADMIN}")
    assert status == 200
    assert "lifetime" in as_json(body) and "landing" in as_json(body)


def test_admin_lockout_after_failed_attempts(srv):
    codes = [call(srv, "/api/stats?key=guess")[0] for _ in range(11)]
    assert codes[:10] == [401] * 10
    assert codes[10] == 403
    # even the right key is refused while locked out
    assert call(srv, f"/api/stats?key={ADMIN}")[0] == 403


@pytest.mark.parametrize("name", ["../relay_server.py", "..%2F..%2Fetc%2Fpasswd", "stats_x.txt", "other_2026-01.jsonl"])
def test_admin_log_download_rejects_unexpected_names(srv, name):
    assert call(srv, f"/api/logs?key={ADMIN}&file={name}")[0] == 404


def test_admin_log_download(srv):
    srv.server._analytics.flush_hourly()
    status, body = call(srv, f"/api/files?key={ADMIN}")
    files = as_json(body)["stats_files"]
    assert status == 200 and files
    status, raw = call(srv, f"/api/logs?key={ADMIN}&file={files[0]}")
    assert status == 200
    assert json.loads(raw.decode().splitlines()[-1])["lifetime"]


def test_x_real_ip_header_is_trusted_on_direct_connections(srv):
    # Characterisation: the API port trusts X-Real-IP from any caller. This is
    # safe only because port 8766 is reachable exclusively through Caddy,
    # which overwrites the header. Rotating the header dodges the lockout.
    for i in range(12):
        assert call(srv, "/api/stats?key=guess", headers={"X-Real-IP": f"10.0.0.{i}"})[0] == 401
