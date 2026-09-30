"""Send / receive input validation, verification dialog, cancel."""

import re
import threading

from app import i18n
from tests.ui.conftest import find_button, find_toplevel, pump, toplevels, widget_text, walk

CODE_RE = re.compile(r"[a-z0-9]{4}-[a-z0-9]{4}")


# ── Send tab ────────────────────────────────────────────────────────

def test_send_without_file_warns(app, dialogs):
    app._on_send()
    assert len(dialogs.warnings) == 1
    assert app.send_btn.cget("state") == "normal"


def test_browse_shows_name_and_size(app, dialogs, tmp_path):
    f = tmp_path / "report.pdf"
    f.write_bytes(b"x" * 2048)
    dialogs.open_file = str(f)
    app._browse_file()
    info = app.file_info_label.cget("text")
    assert "report.pdf" in info and "2.0" in info
    assert app.size_warning_label.cget("text") == ""


def test_browse_cancelled_keeps_previous_file(app, dialogs, tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"1")
    dialogs.open_file = str(f)
    app._browse_file()
    dialogs.open_file = ""
    app._browse_file()
    assert app.file_entry.get() == str(f)


def test_large_file_warning_and_decline(app, dialogs, tmp_path):
    from app.config import VPS_MAX_FILE_SIZE
    big = tmp_path / "huge.iso"
    with open(big, "wb") as fh:           # sparse file: no real disk usage
        fh.truncate(VPS_MAX_FILE_SIZE + 1)
    dialogs.open_file = str(big)
    app._browse_file()
    assert app.size_warning_label.cget("text") != ""
    dialogs.ask_yes_no = False
    app._on_send()
    assert len(dialogs.questions) == 1
    assert app.send_code_label.cget("text") == i18n.t("send_code_placeholder")
    assert app.send_btn.cget("state") == "normal"


def test_send_then_cancel_restores_ui(app, dialogs, relay, tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"data")
    dialogs.open_file = str(f)
    app._browse_file()
    app._on_send()
    pump(app, timeout=0.3)
    assert CODE_RE.fullmatch(app.send_code_label.cget("text"))
    assert app.send_btn.cget("state") == "disabled"
    assert app.recv_btn.cget("state") == "disabled"
    assert app.cancel_btn.cget("state") == "normal"
    assert app.copy_code_btn.cget("state") == "normal"

    app.cancel_btn.invoke()
    assert pump(app, lambda: app.send_btn.cget("state") == "normal", timeout=15)
    assert app.cancel_btn.cget("state") == "disabled"
    assert i18n.t("transfer_cancelled_user") in app.status_box.get("1.0", "end")


def test_copy_session_code(app, dialogs, relay, tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"data")
    dialogs.open_file = str(f)
    app._browse_file()
    app._on_send()
    pump(app, timeout=0.3)
    app.copy_code_btn.invoke()
    assert app.clipboard_get() == app.send_code_label.cget("text")
    app._on_cancel()
    pump(app, lambda: app.send_btn.cget("state") == "normal", timeout=15)


# ── Receive tab ─────────────────────────────────────────────────────

def test_receive_with_empty_code_warns(app, dialogs):
    app._on_receive()
    assert len(dialogs.warnings) == 1


def test_receive_with_short_code_warns(app, dialogs):
    app.recv_code_entry.insert(0, "abc-12")
    app._on_receive()
    assert len(dialogs.warnings) == 1


def test_receive_into_missing_folder_warns(app, dialogs, tmp_path):
    app.recv_code_entry.insert(0, "abcd-1234")
    app._save_dir = str(tmp_path / "does-not-exist")
    app._on_receive()
    assert len(dialogs.warnings) == 1


def test_paste_code_from_clipboard(app):
    app.clipboard_clear()
    app.clipboard_append("  wxyz-9876 \n")
    app._paste_session_code()
    assert app.recv_code_entry.get() == "wxyz-9876"


def test_browse_save_dir(app, dialogs, tmp_path):
    dialogs.open_dir = str(tmp_path)
    app._browse_save_dir()
    assert app._save_dir == str(tmp_path)
    assert app.save_dir_entry.get() == str(tmp_path)


# ── Verification dialog ─────────────────────────────────────────────

def _open_verify(app, code="AB12-CD34"):
    result = []
    t = threading.Thread(target=lambda: result.append(app._verify_connection(code)), daemon=True)
    t.start()
    assert pump(app, lambda: find_toplevel(app, i18n.t("verify_title")) is not None, timeout=5)
    return find_toplevel(app, i18n.t("verify_title")), result, t


def test_verify_dialog_shows_code_and_confirms(app):
    dlg, result, t = _open_verify(app)
    assert "AB12-CD34" in [widget_text(w) for w in walk(dlg)]
    find_button(dlg, i18n.t("btn_codes_match")).invoke()
    assert pump(app, lambda: not t.is_alive(), timeout=5)
    assert result == [True]
    pump(app, timeout=0.1)
    assert toplevels(app) == []


def test_verify_dialog_cancel(app):
    dlg, result, t = _open_verify(app)
    find_button(dlg, i18n.t("btn_cancel_verify")).invoke()
    assert pump(app, lambda: not t.is_alive(), timeout=5)
    assert result == [False]


def test_verify_dialog_window_close_means_reject(app):
    dlg, result, t = _open_verify(app)
    dlg.tk.call(dlg.protocol("WM_DELETE_WINDOW"))  # what the [X] button runs
    assert pump(app, lambda: not t.is_alive(), timeout=5)
    assert result == [False]
