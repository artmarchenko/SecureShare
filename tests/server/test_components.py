"""Relay server building blocks: rate limiting, IP extraction, analytics persistence."""

from __future__ import annotations

import pytest

from tests.helpers.local_relay import load_server_modules


@pytest.fixture(scope="module")
def mods(tmp_path_factory):
    relay, analytics = load_server_modules(tmp_path_factory.mktemp("relay-mods"))
    return relay, analytics


# ── Connection rate limiter ─────────────────────────────────────────

def test_rate_limiter_window_and_concurrency(mods, monkeypatch):
    relay, _ = mods
    monkeypatch.setattr(relay, "RATE_LIMIT_MAX", 3)
    monkeypatch.setattr(relay, "MAX_CONNECTIONS_PER_IP", 2)
    now = [1000.0]
    monkeypatch.setattr(relay.time, "monotonic", lambda: now[0])

    rl = relay.RateLimiter()
    assert rl.check("1.1.1.1")
    rl.connect("1.1.1.1")
    assert rl.check("1.1.1.1")
    rl.connect("1.1.1.1")
    assert not rl.check("1.1.1.1")          # 2 concurrent -> blocked
    rl.disconnect("1.1.1.1")
    assert rl.check("1.1.1.1")               # 3rd attempt in window
    assert not rl.check("1.1.1.1")          # window exhausted
    assert rl.check("2.2.2.2")               # other IPs unaffected
    now[0] += relay.RATE_LIMIT_WINDOW + 1
    assert rl.check("1.1.1.1")


def test_rate_limiter_cleanup(mods, monkeypatch):
    relay, _ = mods
    now = [0.0]
    monkeypatch.setattr(relay.time, "monotonic", lambda: now[0])
    rl = relay.RateLimiter()
    rl.check("a")
    rl.check("b")
    rl.connect("b")
    now[0] += relay.RATE_LIMIT_WINDOW + 1
    assert rl.cleanup() == 1                 # 'a' removed, 'b' still connected
    assert "b" in rl._attempts


# ── Client IP extraction (WebSocket path) ───────────────────────────

class FakeWS:
    def __init__(self, remote, xff=""):
        self.remote_address = (remote, 5555)
        self.request = type("R", (), {"headers": {"X-Forwarded-For": xff} if xff else {}})()


@pytest.mark.parametrize("remote,xff,expected", [
    ("172.18.0.5", "203.0.113.7", "203.0.113.7"),      # via Caddy (docker net)
    ("172.18.0.5", "", "172.18.0.5"),
    ("198.51.100.1", "203.0.113.7", "198.51.100.1"),   # untrusted peer cannot spoof
])
def test_client_ip(mods, monkeypatch, remote, xff, expected):
    relay, _ = mods
    monkeypatch.setattr(relay, "TRUSTED_PROXIES", "172.16.0.0/12")
    server = relay.RelayServer.__new__(relay.RelayServer)
    assert server._get_client_ip(FakeWS(remote, xff)) == expected


# ── Analytics persistence ───────────────────────────────────────────

def test_stats_survive_restart(mods, tmp_path):
    _, analytics = mods
    a = analytics.StatsCollector(tmp_path)
    a.record_connection()
    a.record_session_created()
    a.record_session_completed(10 * 2 ** 20, 42)
    a.record_client_event({"app_version": "3.4.0", "os": "Linux-6", "outcome": "success"})
    a.flush_hourly()

    b = analytics.StatsCollector(tmp_path)
    assert b.lifetime["sessions_completed"] == 1
    assert b.lifetime["bytes_relayed"] == 10 * 2 ** 20
    assert b._versions["3.4.0"] == 1
    assert b._size_dist["10-100MB"] == 1


def test_stats_restore_skips_corrupt_tail(mods, tmp_path):
    _, analytics = mods
    a = analytics.StatsCollector(tmp_path)
    a.record_session_completed(1, 1)
    a.flush_hourly()
    path = a._writer._current_path()
    with open(path, "a", encoding="utf-8") as f:
        f.write('{"broken": \n')
    assert analytics.StatsCollector(tmp_path).lifetime["sessions_completed"] == 1


def test_stats_survive_restart_across_month_boundary(mods, tmp_path, monkeypatch):
    _, analytics = mods
    monkeypatch.setattr(analytics, "_month_key", lambda: "2026-09")
    a = analytics.StatsCollector(tmp_path)
    a.record_session_completed(5, 1)
    a.flush_hourly()
    monkeypatch.setattr(analytics, "_month_key", lambda: "2026-10")   # restart on Oct 1st
    assert analytics.StatsCollector(tmp_path).lifetime["sessions_completed"] == 1


def test_landing_survives_restart(mods, tmp_path):
    _, analytics = mods
    a = analytics.LandingAnalytics(tmp_path)
    a.record_page_view("1.2.3.4", referrer="https://github.com/x", lang="de", screen_w=1920)
    a.record_page_view("1.2.3.4")
    a.record_download("1.2.3.4", asset="windows")
    a.flush()
    b = analytics.LandingAnalytics(tmp_path)
    assert b._total_views == 2
    assert b._downloads_total == 1
    assert b.get_summary()["unique_today"] == 1


def test_unique_visitors_are_not_stored_as_ips(mods, tmp_path):
    _, analytics = mods
    a = analytics.LandingAnalytics(tmp_path)
    a.record_page_view("203.0.113.9")
    a.flush()
    raw = a._writer._current_path().read_text(encoding="utf-8")
    assert "203.0.113.9" not in raw


def test_distribution_dicts_are_capped(mods):
    _, analytics = mods
    d: dict = {}
    for i in range(analytics.MAX_DICT_KEYS + 50):
        analytics._safe_incr(d, f"k{i}")
    assert len(d) == analytics.MAX_DICT_KEYS


def test_admin_key_check(mods, monkeypatch):
    _, analytics = mods
    monkeypatch.setattr(analytics, "ADMIN_KEY", "s3cret")
    assert analytics.verify_admin_key("s3cret")
    assert not analytics.verify_admin_key("s3cre")
    assert not analytics.verify_admin_key("")
    monkeypatch.setattr(analytics, "ADMIN_KEY", "")
    assert not analytics.verify_admin_key("")   # unset key disables admin API


# ── Privacy: no IP addresses in the relay log ───────────────────────

def test_ip_tag_hides_the_address(mods):
    relay, _ = mods
    tag = relay._ip_tag("203.0.113.9")
    assert tag.startswith("c-") and "203.0.113.9" not in tag
    assert relay._ip_tag("203.0.113.9") == tag          # stable within a day
    assert relay._ip_tag("203.0.113.10") != tag


def test_connection_logs_do_not_contain_ips(local_relay, caplog):
    import logging
    import websocket
    caplog.set_level(logging.DEBUG, logger="relay")
    a = websocket.create_connection(local_relay.url, timeout=5)
    a.send("room-for-log-test")
    b = websocket.create_connection(local_relay.url, timeout=5)
    b.send("room-for-log-test")
    a.send_binary(b"x")
    assert b.recv() == b"x"
    a.close()
    b.close()
    import time
    time.sleep(0.3)
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "Peer joined room" in text
    assert "127.0.0.1" not in text


def test_landing_survives_restart_across_month_boundary(mods, tmp_path, monkeypatch):
    _, analytics = mods
    monkeypatch.setattr(analytics, "_month_key", lambda: "2026-09")
    a = analytics.LandingAnalytics(tmp_path)
    a.record_page_view("1.2.3.4")
    a.flush()
    with open(a._writer._current_path(), "a", encoding="utf-8") as f:
        f.write("{broken\n")                                   # corrupt tail is skipped too
    monkeypatch.setattr(analytics, "_month_key", lambda: "2026-10")
    assert analytics.LandingAnalytics(tmp_path)._total_views == 1


def test_restore_prefers_newest_month(mods, tmp_path, monkeypatch):
    _, analytics = mods
    for month, sessions in (("2026-08", 1), ("2026-09", 2)):
        monkeypatch.setattr(analytics, "_month_key", lambda m=month: m)
        c = analytics.StatsCollector(tmp_path)
        c.lifetime["sessions_completed"] = sessions
        c.flush_hourly()
    monkeypatch.setattr(analytics, "_month_key", lambda: "2026-10")
    assert analytics.StatsCollector(tmp_path).lifetime["sessions_completed"] == 2
