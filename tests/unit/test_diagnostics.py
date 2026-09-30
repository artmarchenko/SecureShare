"""Connectivity checks without the GUI (network fully simulated)."""

import socket
import sys
import types

import pytest

from app import diagnostics


class FakeConn:
    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeTLS(FakeConn):
    def getpeercert(self):
        return {"issuer": ((("organizationName", "Let's Encrypt"),),), "notAfter": "Dec 31 2026"}


class FakeContext:
    def wrap_socket(self, raw, server_hostname):
        return FakeTLS()


@pytest.fixture
def results():
    rows, summary = {}, []
    return rows, summary, (lambda k, ok, d, c: rows.__setitem__(k, (ok, d))), (lambda txt, col: summary.append((txt, col)))


@pytest.fixture
def healthy(monkeypatch):
    monkeypatch.setattr(diagnostics.socket, "create_connection", lambda *a, **k: FakeConn())
    monkeypatch.setattr(diagnostics.socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(diagnostics.ssl, "create_default_context", lambda: FakeContext())
    monkeypatch.setattr(diagnostics.time, "sleep", lambda s: None)
    fake_ws = types.SimpleNamespace(create_connection=lambda url, timeout: FakeConn())
    monkeypatch.setitem(sys.modules, "websocket", fake_ws)


def test_all_checks_pass(healthy, results):
    rows, summary, row_cb, sum_cb = results
    assert diagnostics.run_checks(row_cb, sum_cb) == 5
    assert all(ok for ok, _ in rows.values()) and set(rows) == set(diagnostics.CHECKS)
    assert "203.0.113.10" in rows["dns"][1]
    assert "Let's Encrypt" in rows["tls"][1]
    assert summary[-1][1] == diagnostics.OK_COLOR


def test_no_internet_skips_everything(monkeypatch, results):
    rows, summary, row_cb, sum_cb = results

    def down(*a, **k):
        raise OSError("unreachable")
    monkeypatch.setattr(diagnostics.socket, "create_connection", down)
    assert diagnostics.run_checks(row_cb, sum_cb) == 0
    assert not any(ok for ok, _ in rows.values()) and len(rows) == 5
    assert summary == [(summary[0][0], diagnostics.BAD_COLOR)]


def test_dns_failure_skips_the_rest(healthy, monkeypatch, results):
    rows, summary, row_cb, sum_cb = results

    def no_dns(host):
        raise socket.gaierror("nope")
    monkeypatch.setattr(diagnostics.socket, "gethostbyname", no_dns)
    assert diagnostics.run_checks(row_cb, sum_cb) == 1
    assert rows["internet"][0] is True
    assert [rows[k][0] for k in ("dns", "tls", "websocket", "latency")] == [False] * 4


def test_websocket_blocked_but_https_works(healthy, monkeypatch, results):
    rows, summary, row_cb, sum_cb = results

    def ws_blocked(url, timeout):
        raise ConnectionResetError("proxy strips Upgrade")
    monkeypatch.setitem(sys.modules, "websocket", types.SimpleNamespace(create_connection=ws_blocked))
    monkeypatch.setattr(diagnostics.urllib.request, "urlopen",
                        lambda url, timeout: types.SimpleNamespace(status=200))
    assert diagnostics.run_checks(row_cb, sum_cb) == 5
    assert "HTTP" in rows["websocket"][1]


def test_partial_result_is_a_warning(healthy, monkeypatch, results):
    rows, summary, row_cb, sum_cb = results

    def bad_tls():
        raise OSError("handshake failed")
    monkeypatch.setattr(diagnostics.ssl, "create_default_context", bad_tls)
    assert diagnostics.run_checks(row_cb, sum_cb) == 4
    assert rows["tls"][0] is False
    assert summary[-1][1] == diagnostics.WARN_COLOR
