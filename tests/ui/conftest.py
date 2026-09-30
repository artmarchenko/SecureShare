"""
GUI test harness for the CustomTkinter app.

The real `App` window is created and driven programmatically:
  * `pump()` runs the Tk event loop until a condition holds (instead of mainloop)
  * blocking dialogs (file pickers, message boxes, browser) are stubbed
  * helpers find widgets by text and "click" them via .invoke()
"""

from __future__ import annotations

import gc
import time
from dataclasses import dataclass, field
from typing import Callable

import customtkinter as ctk
import pytest


def pump(app, until: Callable[[], bool] | None = None, timeout: float = 5.0, interval_ms: int = 10) -> bool:
    """Run the real Tk mainloop until `until()` is true or the timeout expires.

    A real mainloop (not update()) is required: worker threads call
    `app.after()`, which tkinter only allows while the main thread is
    dispatching events in mainloop.
    """
    deadline = time.monotonic() + timeout
    outcome = [until is None]

    def tick():
        if until is not None and until():
            outcome[0] = True
            app.quit()
        elif time.monotonic() >= deadline:
            app.quit()
        else:
            app.after(interval_ms, tick)

    app.after(interval_ms, tick)
    app.mainloop()
    return outcome[0]


def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)


def widget_text(widget) -> str | None:
    try:
        text = widget.cget("text")
    except Exception:
        return None
    return text if isinstance(text, str) else None


def find_button(root, text: str):
    for w in walk(root):
        if isinstance(w, ctk.CTkButton) and widget_text(w) == text:
            return w
    return None


def toplevels(app):
    return [w for w in app.winfo_children() if isinstance(w, ctk.CTkToplevel) and w.winfo_exists()]


def find_toplevel(app, title_part: str):
    for w in toplevels(app):
        if title_part in w.title():
            return w
    return None


def log_text(app) -> str:
    return app.status_box.get("1.0", "end")


def create_app(gui, attempts: int = 3):
    """Create the main window, retrying transient Tcl start-up failures.

    On Windows, Tk initialisation occasionally fails to read its own
    init.tcl/tk.tcl ("couldn't read file ... No error"), typically while an
    antivirus scanner holds the file. That is an environment hiccup, not an
    application bug, so we retry a few times before giving up.
    """
    import tkinter
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            return gui.App()
        except tkinter.TclError as exc:
            last = exc
            gc.collect()
            time.sleep(0.2 * (attempt + 1))
    pytest.skip(f"cannot create Tk window (no display?): {last}")


@dataclass
class Dialogs:
    """Records calls to stubbed modal dialogs; answers are configurable."""
    open_file: str = ""
    open_dir: str = ""
    save_file: str = ""
    ask_yes_no: bool = True
    warnings: list = field(default_factory=list)
    questions: list = field(default_factory=list)
    opened_urls: list = field(default_factory=list)


@pytest.fixture
def dialogs(monkeypatch):
    from app import gui
    d = Dialogs()
    monkeypatch.setattr(gui.filedialog, "askopenfilename", lambda **kw: d.open_file)
    monkeypatch.setattr(gui.filedialog, "askdirectory", lambda **kw: d.open_dir)
    monkeypatch.setattr(gui.filedialog, "asksaveasfilename", lambda **kw: d.save_file)
    monkeypatch.setattr(gui.messagebox, "showwarning", lambda title, msg: d.warnings.append((title, msg)))

    def _ask(title, msg):
        d.questions.append((title, msg))
        return d.ask_yes_no
    monkeypatch.setattr(gui.messagebox, "askyesno", _ask)
    monkeypatch.setattr(gui.webbrowser, "open", lambda url: d.opened_urls.append(url))
    return d


@pytest.fixture
def no_update_check(monkeypatch):
    from app import gui
    calls = []
    monkeypatch.setattr(gui, "check_for_update", lambda force=False: calls.append(force) or None)
    return calls


@pytest.fixture
def app(dialogs, no_update_check):
    from app import gui, i18n
    i18n.set_language("uk", save=True)
    window = create_app(gui)
    pump(window, timeout=0.3)
    yield window
    try:
        for top in toplevels(window):
            top.destroy()
        window.update()
        window.destroy()
    except Exception:
        pass
    # Free Tcl objects on the main thread now; otherwise the GC may finalise
    # them later while the next test creates a new Tk interpreter, which
    # intermittently breaks Tk initialisation on Windows.
    gc.collect()
