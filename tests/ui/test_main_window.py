import re

import customtkinter as ctk
import pytest

from app import i18n
from tests.ui.conftest import create_app, find_button, log_text, pump, walk, widget_text

LABELS = {"uk": "UA", "en": "EN", "de": "DE"}


def visible_texts(app) -> list[str]:
    return [t for w in walk(app) if (t := widget_text(w))]


def test_window_builds_and_shows_version(app):
    from app.config import APP_VERSION
    assert APP_VERSION in app.title()
    assert app.send_btn.cget("state") == "normal"
    assert app.cancel_btn.cget("state") == "disabled"


def test_startup_tip_is_logged(app):
    assert pump(app, lambda: log_text(app).strip() != "", timeout=3)
    assert re.match(r"\[\d\d:\d\d:\d\d\] ", log_text(app))


def test_startup_update_check_is_scheduled(app, no_update_check):
    assert pump(app, lambda: no_update_check == [False], timeout=5)


@pytest.mark.parametrize("code", ["uk", "en", "de"])
def test_no_raw_translation_keys_on_screen(app, code):
    app._on_language_change(LABELS[code])
    pump(app, timeout=0.2)
    keys = set(i18n._languages[code])
    raw = [t for t in visible_texts(app) if t in keys]
    assert raw == [], f"untranslated keys visible in {code}: {raw}"


@pytest.mark.parametrize("code,send_text", [("en", "Send"), ("de", "Senden"), ("uk", "Надіслати")])
def test_language_switch_updates_widgets(app, code, send_text):
    app._on_language_change(LABELS[code])
    pump(app, timeout=0.2)
    assert send_text in app.send_btn.cget("text")
    assert i18n.get_language() == code


def test_language_choice_survives_restart(app, dialogs, no_update_check):
    from app import gui
    app._on_language_change("DE")
    pump(app, timeout=0.2)
    app.destroy()
    again = create_app(gui)
    try:
        pump(again, timeout=0.2)
        assert "Senden" in again.send_btn.cget("text")
        assert again._lang_menu.get() == "DE"
    finally:
        again.destroy()
        i18n.set_language("uk")


@pytest.mark.parametrize("size", ["default", "minimum"])
def test_footer_and_status_fully_visible(app, size):
    # U1: at the default size (and at the minimum size) nothing at the bottom is clipped
    if size == "minimum":
        import tkinter
        w, h = tkinter.Tk.wm_minsize(app)   # CTk.minsize() getter is broken; ask Tk (physical px)
        app.geometry(f"{w}x{h}")
    pump(app, timeout=0.4)
    for widget in (app._copyright_lbl, app.cancel_btn):
        assert widget.winfo_ismapped()
        bottom = widget.winfo_rooty() + widget.winfo_height()
        assert bottom <= app.winfo_rooty() + app.winfo_height(), f"{widget} is clipped"


def test_copy_log_puts_text_on_clipboard(app):
    pump(app, lambda: log_text(app).strip() != "", timeout=3)
    find_button(app, i18n.t("btn_copy_log")).invoke()
    pump(app, timeout=0.1)
    assert app.clipboard_get().strip() != ""


def test_save_log_writes_file(app, dialogs, tmp_path):
    pump(app, lambda: log_text(app).strip() != "", timeout=3)
    dialogs.save_file = str(tmp_path / "log.txt")
    app._save_log()
    content = (tmp_path / "log.txt").read_text(encoding="utf-8")
    assert content.startswith("SecureShare v")


def test_donate_opens_browser(app, dialogs):
    from app.config import DONATE_URL
    app._tb_donate_btn.invoke()
    assert dialogs.opened_urls == [DONATE_URL]


def test_help_window_opens_once(app):
    app._show_help()
    app._show_help()
    pump(app, timeout=0.2)
    helps = [w for w in app.winfo_children()
             if isinstance(w, ctk.CTkToplevel) and i18n.t("help_title") in w.title()]
    assert len(helps) == 1
