import os

import pytest

from app import telemetry


@pytest.fixture(autouse=True)
def clean_settings():
    if os.path.exists(telemetry._SETTINGS_FILE):
        os.remove(telemetry._SETTINGS_FILE)
    yield
    if os.path.exists(telemetry._SETTINGS_FILE):
        os.remove(telemetry._SETTINGS_FILE)


def _boom() -> Exception:
    try:
        raise ValueError(f"failed reading {os.path.expanduser('~')}\\secret\\file.txt")
    except ValueError as exc:
        return exc


# ── Defaults (characterises current behaviour, see B2) ─────────────

def test_session_telemetry_is_off_by_default(telemetry_sink):
    assert telemetry.is_telemetry_enabled() is False
    telemetry.report_session(role="sender", outcome="success", file_size=10)
    assert telemetry_sink == []


def test_crash_reporting_is_on_by_default(telemetry_sink):
    # B2: documented as opt-in, but currently opt-out with no UI toggle.
    assert telemetry.is_crash_reporting_enabled() is True
    telemetry.report_crash(_boom(), state="send_worker")
    assert len(telemetry_sink) == 1
    assert telemetry_sink[0][0].endswith("/api/crash")


def test_toggles_persist(telemetry_sink):
    telemetry.set_crash_reporting_enabled(False)
    telemetry.set_telemetry_enabled(True)
    assert telemetry.is_crash_reporting_enabled() is False
    assert telemetry.is_telemetry_enabled() is True
    telemetry.report_crash(_boom())
    telemetry.report_session(role="receiver", outcome="error", file_size=5, error_type="OSError")
    assert [url.rsplit("/", 1)[-1] for url, _ in telemetry_sink] == ["telemetry"]


# ── Payload privacy ─────────────────────────────────────────────────

def test_crash_report_payload_is_anonymous(telemetry_sink):
    telemetry.report_crash(_boom(), state="x" * 100, log_tail="ip 10.1.2.3 C:\\Users\\bob\\a.txt /home/bob/b")
    report = telemetry_sink[0][1]
    home = os.path.expanduser("~")
    assert home not in report["traceback"]
    assert "10.1.2.3" not in report["log_tail"]
    assert "bob" not in report["log_tail"]
    assert len(report["state"]) == 50
    assert set(report) >= {"crash_id", "app_version", "os", "error_type", "traceback"}


def test_session_event_has_no_exact_size(telemetry_sink):
    telemetry.set_telemetry_enabled(True)
    telemetry.report_session(role="sender", outcome="success", file_size=123_456_789, duration_s=10 ** 9)
    event = telemetry_sink[0][1]
    assert event["file_size_range"] == "100-500MB"
    assert event["duration_s"] == 86400 * 7
    assert event["error_type"] == ""


@pytest.mark.parametrize("size,bucket", [
    (0, "<1MB"),
    (5 * 2 ** 20, "1-10MB"),
    (50 * 2 ** 20, "10-100MB"),
    (700 * 2 ** 20, "500MB-1GB"),
    (3 * 2 ** 30, "3GB+"),
])
def test_file_size_bucket(size, bucket):
    assert telemetry._file_size_bucket(size) == bucket


def test_crash_id_is_random():
    assert telemetry._session_id() != telemetry._session_id()


def test_excepthook_reports_and_chains(telemetry_sink, monkeypatch):
    chained = []
    monkeypatch.setattr(telemetry, "_original_excepthook", lambda *a: chained.append(a[0]))
    exc = _boom()
    telemetry._crash_excepthook(type(exc), exc, exc.__traceback__)
    assert chained == [ValueError]
    assert telemetry_sink and telemetry_sink[0][1]["state"] == "unhandled"
