"""
SecureShare — Internationalization (i18n) module.

Loads JSON translation dictionaries from app/lang/ and provides
a simple t(key, **kwargs) function for translating UI strings.

Usage:
    from app.i18n import t, set_language, get_language, available_languages

    set_language("en")
    label.configure(text=t("btn_send"))
    msg = t("relay_reconnecting", delay=5, attempt=2, max=5)
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger(__name__)

# ── Language settings persistence ─────────────────────────────────
_SETTINGS_DIR = Path(os.environ.get("APPDATA", Path.home())) / "SecureShare"
_SETTINGS_FILE = _SETTINGS_DIR / "language.json"

# ── Default language ──────────────────────────────────────────────
_DEFAULT_LANG = "uk"

# ── State ─────────────────────────────────────────────────────────
_current_lang: str = _DEFAULT_LANG
_strings: dict[str, str] = {}
_fallback: dict[str, str] = {}          # Ukrainian as fallback
_languages: dict[str, dict] = {}        # code → full dictionary
_on_language_change: list[Callable] = []  # callbacks


# ══════════════════════════════════════════════════════════════════
#  Resolve lang/ directory (works both in dev and PyInstaller .exe)
# ══════════════════════════════════════════════════════════════════

def _lang_dir() -> Path:
    """Return the absolute path to the lang/ directory."""
    if getattr(sys, "frozen", False):
        # PyInstaller: files are in sys._MEIPASS
        base = Path(sys._MEIPASS)  # type: ignore[attr-defined]
    else:
        base = Path(__file__).resolve().parent
    return base / "lang"


# ══════════════════════════════════════════════════════════════════
#  Load / save settings
# ══════════════════════════════════════════════════════════════════

def _load_saved_language() -> str:
    """Load the user's preferred language from settings file."""
    try:
        if _SETTINGS_FILE.exists():
            with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("language", _DEFAULT_LANG)
    except Exception as exc:
        log.debug("Failed to load language setting: %s", exc)
    return _DEFAULT_LANG


def _save_language(code: str) -> None:
    """Persist the language choice to disk."""
    try:
        _SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
        with open(_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump({"language": code}, f)
    except Exception as exc:
        log.debug("Failed to save language setting: %s", exc)


# ══════════════════════════════════════════════════════════════════
#  Load dictionaries
# ══════════════════════════════════════════════════════════════════

def _load_dict(path: Path) -> dict[str, str]:
    """Load a JSON dictionary file, returning flat key→string mapping."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Remove _meta key
        data.pop("_meta", None)
        return data
    except Exception as exc:
        log.error("Failed to load language file %s: %s", path, exc)
        return {}


def _load_all() -> None:
    """Scan lang/ directory and load all available dictionaries."""
    global _languages, _fallback
    lang_path = _lang_dir()
    if not lang_path.is_dir():
        log.warning("Language directory not found: %s", lang_path)
        return

    for json_file in sorted(lang_path.glob("*.json")):
        code = json_file.stem  # e.g. "uk", "en", "de"
        _languages[code] = _load_dict(json_file)
        log.debug("Loaded language: %s (%d keys)", code, len(_languages[code]))

    # Ukrainian is the fallback (always present)
    _fallback = _languages.get("uk", {})


# ══════════════════════════════════════════════════════════════════
#  Public API
# ══════════════════════════════════════════════════════════════════

def init() -> None:
    """Initialize i18n: load all dictionaries, restore saved language."""
    _load_all()
    saved = _load_saved_language()
    if saved in _languages:
        set_language(saved, save=False)
    else:
        set_language(_DEFAULT_LANG, save=False)
    log.info("i18n initialized: lang=%s, available=%s", _current_lang, list(_languages.keys()))


def t(key: str, **kwargs) -> str:
    """
    Translate a key to the current language.

    If the key is missing in the current language, falls back to Ukrainian.
    If missing everywhere, returns the key itself (for debugging).

    Supports format placeholders: t("eta_hours", h=2, m=15)
    """
    raw = _strings.get(key) or _fallback.get(key) or key
    if kwargs:
        try:
            return raw.format(**kwargs)
        except (KeyError, IndexError, ValueError) as exc:
            log.debug("Format error for key '%s': %s", key, exc)
            return raw
    return raw


def set_language(code: str, save: bool = True) -> None:
    """Switch the active language."""
    global _current_lang, _strings
    if code not in _languages:
        log.warning("Language '%s' not available, keeping '%s'", code, _current_lang)
        return
    _current_lang = code
    _strings = _languages[code]
    if save:
        _save_language(code)
    log.info("Language set to: %s", code)
    # Notify listeners
    for cb in _on_language_change:
        try:
            cb(code)
        except Exception as exc:
            log.debug("Language change callback error: %s", exc)


def get_language() -> str:
    """Return the current language code."""
    return _current_lang


def available_languages() -> list[str]:
    """Return list of available language codes, e.g. ['de', 'en', 'uk']."""
    return sorted(_languages.keys())


def get_language_name(code: str) -> str:
    """Return a human-readable label for a language code."""
    names = {"uk": "Українська", "en": "English", "de": "Deutsch"}
    return names.get(code, code.upper())


def on_language_change(callback: Callable) -> None:
    """Register a callback to be called when the language changes.

    The callback receives the new language code as its argument.
    """
    _on_language_change.append(callback)
