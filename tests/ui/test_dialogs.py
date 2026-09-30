"""Diagnostics and update dialogs (no real network)."""

import socket

from app import i18n, updater
from app.updater import ReleaseInfo
from tests.ui.conftest import find_button, find_toplevel, pump


# ── Diagnostics ─────────────────────────────────────────────────────

def _diag_summary(app):
    win = find_toplevel(app, i18n.t("diag_title"))
    labels = [w for w in win.winfo_children() if w.winfo_class() == "Frame" or hasattr(w, "cget")]
    for w in labels:
        try:
            text = w.cget("text")
        except Exception:
            continue
        if isinstance(text, str) and "/5" in text:
            return text
    return ""


def test_diagnostics_without_internet(app):
    # The autouse network guard makes every external connection fail.
    app._run_diagnostics()
    assert pump(app, lambda: _diag_summary(app) != "", timeout=10)
    assert "0/5" in _diag_summary(app)


def test_diagnostics_dns_failure(app, monkeypatch):
    from app import diagnostics as diagnostics_window

    class Dummy:
        def close(self):
            pass

    monkeypatch.setattr(diagnostics_window.socket, "create_connection", lambda *a, **k: Dummy())

    def no_dns(host):
        raise socket.gaierror("no dns")
    monkeypatch.setattr(diagnostics_window.socket, "gethostbyname", no_dns)
    app._run_diagnostics()
    assert pump(app, lambda: _diag_summary(app) != "", timeout=10)
    assert "1/5" in _diag_summary(app)


def test_diagnostics_window_is_single_instance(app):
    app._run_diagnostics()
    app._run_diagnostics()
    pump(app, timeout=0.2)
    wins = [w for w in app.winfo_children() if hasattr(w, "title") and i18n.t("diag_title") in w.title()]
    assert len(wins) == 1


def test_privacy_toggles_reflect_and_change_settings(app):
    # B2: crash reports (default on) and usage statistics (default off) can be toggled
    from app import telemetry
    telemetry.set_crash_reporting_enabled(True)
    telemetry.set_telemetry_enabled(False)
    app._run_diagnostics()
    pump(app, timeout=0.2)
    assert app._diag_crash_switch.get() == 1
    assert app._diag_stats_switch.get() == 0
    app._diag_crash_switch.toggle()
    app._diag_stats_switch.toggle()
    assert telemetry.is_crash_reporting_enabled() is False
    assert telemetry.is_telemetry_enabled() is True
    telemetry.set_crash_reporting_enabled(True)
    telemetry.set_telemetry_enabled(False)


# ── Update dialog ───────────────────────────────────────────────────

RELEASE = ReleaseInfo(
    tag="v9.9.9", version="9.9.9", name="v9.9.9",
    body="## SecureShare v9.9.9\n\n### Changes\n- abc1234 fix: faster uploads\n- def5678 feat: dark mode\n\n### Download\n...",
    html_url="https://example.invalid/release", published="2026-10-01T00:00:00Z",
    win_download="", checksums_url="",
)


def test_update_dialog_shows_clean_release_notes(app):
    app._show_update_dialog(RELEASE)
    pump(app, timeout=0.2)
    win = find_toplevel(app, i18n.t("update_title"))
    assert win is not None
    boxes = [w for w in win.winfo_children() if w.__class__.__name__ == "CTkTextbox"]
    notes = boxes[0].get("1.0", "end").strip()
    assert notes == "• fix: faster uploads\n• feat: dark mode"


def test_update_dialog_skip_version(app):
    updater.clear_skipped()
    app._show_update_dialog(RELEASE)
    pump(app, timeout=0.2)
    win = find_toplevel(app, i18n.t("update_title"))
    find_button(win, i18n.t("btn_skip_version")).invoke()
    pump(app, timeout=0.2)
    assert updater.is_version_skipped("9.9.9")
    assert find_toplevel(app, i18n.t("update_title")) is None
    updater.clear_skipped()


def test_update_dialog_github_button_opens_release(app, dialogs):
    app._show_update_dialog(RELEASE)
    pump(app, timeout=0.2)
    win = find_toplevel(app, i18n.t("update_title"))
    find_button(win, "🌐 GitHub").invoke()
    assert dialogs.opened_urls == ["https://example.invalid/release"]


def test_no_auto_update_button_when_running_from_source(app):
    # Not a frozen build -> only the GitHub / Skip / Later buttons.
    app._show_update_dialog(RELEASE)
    pump(app, timeout=0.2)
    win = find_toplevel(app, i18n.t("update_title"))
    assert find_button(win, i18n.t("btn_update_now")) is None


def test_manual_update_check_reports_up_to_date(app, no_update_check):
    app._check_updates_manual()
    from app.config import APP_VERSION
    expected = i18n.t("update_up_to_date", version=APP_VERSION)
    assert pump(app, lambda: expected in app.status_box.get("1.0", "end"), timeout=5)
    assert True in no_update_check
