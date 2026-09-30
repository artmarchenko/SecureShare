#!/usr/bin/env python3
"""
Capture screenshots of the SecureShare UI for visual review.

Shoots every language (uk/en/de) x screen (send, send with a file and a
session code, receive, verification dialog, diagnostics) and writes PNGs
named <platform>_<lang>_<screen>.png into the output directory.

No network access: the update check is stubbed and diagnostics run with
all connections failing. Settings are isolated in a temporary APPDATA.

Run:
    python scripts/ui_screenshots.py [output_dir]     # needs a display
    xvfb-run -a python scripts/ui_screenshots.py out  # headless Linux
Requires Pillow (ImageGrab).
"""

from __future__ import annotations

import os
import platform
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["APPDATA"] = tempfile.mkdtemp(prefix="secureshare-shots-")

from PIL import ImageGrab  # noqa: E402

LANG_LABELS = {"uk": "UA", "en": "EN", "de": "DE"}


def pump(app, seconds: float = 0.4, until=None) -> None:
    """Run the real mainloop (worker threads may call app.after())."""
    deadline = time.monotonic() + seconds

    def tick():
        if (until is not None and until()) or time.monotonic() >= deadline:
            app.quit()
        else:
            app.after(20, tick)
    app.after(20, tick)
    app.mainloop()


def settle(app, seconds: float = 0.4) -> None:
    pump(app, seconds)


def grab(window, path: Path) -> None:
    window.lift()
    window.attributes("-topmost", True)
    settle(window.winfo_toplevel(), 0.3)
    x, y = window.winfo_rootx(), window.winfo_rooty()
    w, h = window.winfo_width(), window.winfo_height()
    ImageGrab.grab(bbox=(x, y, x + w, y + h), all_screens=True).save(path)
    window.attributes("-topmost", False)
    print(f"  {path.name}  {w}x{h}")


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "ui-screenshots").resolve()
    out.mkdir(parents=True, exist_ok=True)
    tag = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(platform.system(), "other")

    from app import gui, i18n

    gui.check_for_update = lambda force=False: None       # no GitHub call

    def offline(*args, **kwargs):
        raise OSError("offline (screenshot mode)")
    from app import diagnostics as diagnostics_window
    diagnostics_window.socket.create_connection = offline  # diagnostics stay local
    diagnostics_window.socket.gethostbyname = offline

    sample = Path(tempfile.mkdtemp()) / "Quarterly report 2026.pdf"
    sample.write_bytes(b"x" * 3_400_000)

    app = gui.App()
    app.geometry(f"{gui.App.WIDTH}x{gui.App.HEIGHT}+40+40")
    settle(app, 1.0)
    print(f"Tk scaling: {app.tk.call('tk', 'scaling'):.2f}, window {app.winfo_width()}x{app.winfo_height()}")

    for code, label in LANG_LABELS.items():
        app._lang_menu.set(label)
        app._on_language_change(label)
        settle(app)

        # Send tab, idle
        app.tabs.set(app._tab_send_name)
        app.file_entry.configure(state="normal")
        app.file_entry.delete(0, "end")
        app.file_entry.configure(state="readonly")
        app.file_info_label.configure(text="")
        app.send_code_label.configure(text=i18n.t("send_code_placeholder"))
        settle(app)
        grab(app, out / f"{tag}_{code}_send.png")

        # Send tab with a file and a session code
        app.file_entry.configure(state="normal")
        app.file_entry.insert(0, str(sample))
        app.file_entry.configure(state="readonly")
        app._update_file_info(str(sample))
        app.send_code_label.configure(text="k7pq-2xma")
        settle(app)
        grab(app, out / f"{tag}_{code}_send_ready.png")

        # Receive tab
        app.tabs.set(app._tab_recv_name)
        app.recv_code_entry.delete(0, "end")
        app.recv_code_entry.insert(0, "k7pq-2xma")
        settle(app)
        grab(app, out / f"{tag}_{code}_receive.png")
        app.tabs.set(app._tab_send_name)

        # Verification dialog
        answer: list = []
        worker = threading.Thread(target=lambda: answer.append(app._verify_connection("E555-EB8B")), daemon=True)
        worker.start()

        def find_dialog():
            return next((w for w in app.winfo_children()
                         if hasattr(w, "title") and w.winfo_exists() and i18n.t("verify_title") in w.title()), None)
        pump(app, 5, until=find_dialog)
        dialog = find_dialog()
        settle(app)
        grab(dialog, out / f"{tag}_{code}_verify.png")
        dialog.tk.call(dialog.protocol("WM_DELETE_WINDOW"))
        pump(app, 5, until=lambda: not worker.is_alive())

        # Diagnostics (all checks fail quickly — no network)
        app._run_diagnostics()
        settle(app, 1.5)
        grab(app._diag_win, out / f"{tag}_{code}_diagnostics.png")
        app._diag_win.destroy()
        app._diag_win = None
        settle(app, 0.2)

    app.destroy()
    print(f"Saved to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
