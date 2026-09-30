"""Full transfers where one side is the real GUI and the other a headless client."""

import os
import re
import threading

from app import i18n
from app.config import VPS_CHUNK_SIZE
from app.ws_relay import VPSRelayReceiver, VPSRelaySender
from tests.ui.conftest import find_button, find_toplevel, log_text, pump

CODE_RE = re.compile(r"[a-z0-9]{4}-[a-z0-9]{4}")


def _confirm_verify_dialog(app, timeout=15):
    title = i18n.t("verify_title")
    assert pump(app, lambda: find_toplevel(app, title) is not None, timeout=timeout), "verify dialog did not appear"
    find_button(find_toplevel(app, title), i18n.t("btn_codes_match")).invoke()


def test_gui_sends_file_to_headless_receiver(app, dialogs, relay, tmp_path):
    src = tmp_path / "photo.raw"
    src.write_bytes(os.urandom(6 * VPS_CHUNK_SIZE + 99))
    inbox = tmp_path / "inbox"
    inbox.mkdir()

    dialogs.open_file = str(src)
    app._browse_file()
    app.send_btn.invoke()
    assert pump(app, lambda: CODE_RE.fullmatch(app.send_code_label.cget("text")), timeout=3)
    code = app.send_code_label.cget("text")

    received = []
    receiver = VPSRelayReceiver(code, inbox, on_verify=lambda c: True)
    worker = threading.Thread(target=lambda: received.append(receiver.receive()), daemon=True)
    worker.start()

    _confirm_verify_dialog(app)
    done_text = i18n.t("state_done")
    assert pump(app, lambda: app.status_indicator.cget("text") == done_text, timeout=60)
    assert pump(app, lambda: not worker.is_alive(), timeout=15)

    assert received[0].read_bytes() == src.read_bytes()
    assert app.progress_bar.get() == 1.0
    assert app.send_btn.cget("state") == "normal"
    assert app.cancel_btn.cget("state") == "disabled"
    assert i18n.t("transfer_complete_send") in log_text(app)


def test_gui_receives_file_from_headless_sender(app, relay, tmp_path):
    src = tmp_path / "archive.zip"
    src.write_bytes(os.urandom(3 * VPS_CHUNK_SIZE))
    inbox = tmp_path / "downloads"
    inbox.mkdir()
    code = "rcv1-" + os.urandom(2).hex()

    sent = []
    sender = VPSRelaySender(code, src, on_verify=lambda c: True)
    worker = threading.Thread(target=lambda: sent.append(sender.send()), daemon=True)
    worker.start()

    app._save_dir = str(inbox)
    app.recv_code_entry.insert(0, code.upper())   # user may type in upper case
    app.recv_btn.invoke()

    _confirm_verify_dialog(app)
    done_text = i18n.t("state_done")
    assert pump(app, lambda: app.status_indicator.cget("text") == done_text, timeout=60)
    assert pump(app, lambda: not worker.is_alive(), timeout=15)

    assert sent == [True]
    assert (inbox / "archive.zip").read_bytes() == src.read_bytes()
    assert str(inbox / "archive.zip") in log_text(app)


def test_gui_rejecting_code_aborts_both_sides(app, dialogs, relay, tmp_path):
    src = tmp_path / "x.bin"
    src.write_bytes(b"secret")
    dialogs.open_file = str(src)
    app._browse_file()
    app.send_btn.invoke()
    assert pump(app, lambda: CODE_RE.fullmatch(app.send_code_label.cget("text")), timeout=3)

    received = []
    receiver = VPSRelayReceiver(app.send_code_label.cget("text"), tmp_path, on_verify=lambda c: True)
    worker = threading.Thread(target=lambda: received.append(receiver.receive()), daemon=True)
    worker.start()

    title = i18n.t("verify_title")
    assert pump(app, lambda: find_toplevel(app, title) is not None, timeout=15)
    find_button(find_toplevel(app, title), i18n.t("btn_cancel_verify")).invoke()

    assert pump(app, lambda: app.send_btn.cget("state") == "normal", timeout=30)
    assert pump(app, lambda: not worker.is_alive(), timeout=15)
    assert received == [None]
    assert app.status_indicator.cget("text") == i18n.t("state_error")


# ── Status indicator sequence (characterisation for the typed-state refactor) ──

def _record_states(app, monkeypatch):
    seen = []
    original = type(app)._set_state

    def recording(self, state):
        if not seen or seen[-1] != state:
            seen.append(state)
        return original(self, state)
    monkeypatch.setattr(type(app), "_set_state", recording)
    return seen


def test_state_sequence_gui_sender(app, dialogs, relay, tmp_path, monkeypatch):
    states = _record_states(app, monkeypatch)
    src = tmp_path / "s.bin"
    src.write_bytes(os.urandom(2 * VPS_CHUNK_SIZE))
    dialogs.open_file = str(src)
    app._browse_file()
    app.send_btn.invoke()
    assert pump(app, lambda: CODE_RE.fullmatch(app.send_code_label.cget("text")), timeout=3)
    receiver = VPSRelayReceiver(app.send_code_label.cget("text"), tmp_path / "in", on_verify=lambda c: True)
    (tmp_path / "in").mkdir()
    worker = threading.Thread(target=receiver.receive, daemon=True)
    worker.start()
    _confirm_verify_dialog(app)
    assert pump(app, lambda: app.status_indicator.cget("text") == i18n.t("state_done"), timeout=60)
    pump(app, lambda: not worker.is_alive(), timeout=15)
    assert states == ["idle", "connecting", "waiting", "key_exchange", "verifying",
                      "waiting", "transferring", "waiting", "done"]


def test_state_sequence_gui_receiver(app, relay, tmp_path, monkeypatch):
    states = _record_states(app, monkeypatch)
    src = tmp_path / "r.bin"
    src.write_bytes(os.urandom(2 * VPS_CHUNK_SIZE))
    inbox = tmp_path / "in"
    inbox.mkdir()
    code = "stat-" + os.urandom(2).hex()
    sender = VPSRelaySender(code, src, on_verify=lambda c: True)
    worker = threading.Thread(target=sender.send, daemon=True)
    worker.start()
    app._save_dir = str(inbox)
    app.recv_code_entry.insert(0, code)
    app.recv_btn.invoke()
    _confirm_verify_dialog(app)
    assert pump(app, lambda: app.status_indicator.cget("text") == i18n.t("state_done"), timeout=60)
    pump(app, lambda: not worker.is_alive(), timeout=15)
    assert states == ["idle", "connecting", "waiting", "key_exchange", "verifying",
                      "waiting", "transferring", "done"]


def test_state_sequence_rejected_code(app, dialogs, relay, tmp_path, monkeypatch):
    states = _record_states(app, monkeypatch)
    src = tmp_path / "x.bin"
    src.write_bytes(b"secret")
    dialogs.open_file = str(src)
    app._browse_file()
    app.send_btn.invoke()
    assert pump(app, lambda: CODE_RE.fullmatch(app.send_code_label.cget("text")), timeout=3)
    receiver = VPSRelayReceiver(app.send_code_label.cget("text"), tmp_path, on_verify=lambda c: True)
    worker = threading.Thread(target=receiver.receive, daemon=True)
    worker.start()
    title = i18n.t("verify_title")
    assert pump(app, lambda: find_toplevel(app, title) is not None, timeout=15)
    find_button(find_toplevel(app, title), i18n.t("btn_cancel_verify")).invoke()
    assert pump(app, lambda: app.send_btn.cget("state") == "normal", timeout=30)
    pump(app, lambda: not worker.is_alive(), timeout=15)
    assert states[-1] == "error"
    assert states[:5] == ["idle", "connecting", "waiting", "key_exchange", "verifying"]
