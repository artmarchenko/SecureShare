"""
SecureShare — packaging smoke test (`SecureShare.exe --self-test`).

Run by CI right after PyInstaller: builds the main window, checks that the
bundled resources (translations, icons) are present, then exits without
entering the main loop and without any network access.

Exit code 0 = OK, 1 = a check failed.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

log = logging.getLogger(__name__)

EXPECTED_LANGUAGES = ("uk", "en", "de")


def _resource_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent


def run() -> int:
    from . import i18n
    from .gui import App

    problems: list[str] = []

    for rel in ("assets/SecureShare.ico", "assets/icon_32.png"):
        if not (_resource_root() / rel).is_file():
            problems.append(f"missing resource: {rel}")

    app = App()
    try:
        app.update()
        available = i18n.available_languages()
        for code in EXPECTED_LANGUAGES:
            if code not in available:
                problems.append(f"language not bundled: {code}")
                continue
            i18n.set_language(code, save=False)
            if i18n.t("btn_send") == "btn_send":
                problems.append(f"language has no strings: {code}")
        app.send_btn.cget("text")
    finally:
        app.destroy()

    for p in problems:
        log.error("Self-test: %s", p)
    if problems:
        return 1
    log.info("Self-test OK (languages: %s)", ", ".join(EXPECTED_LANGUAGES))
    return 0
