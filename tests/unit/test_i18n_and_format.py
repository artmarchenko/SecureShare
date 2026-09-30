import json

import pytest

from app import i18n


@pytest.fixture
def lang(monkeypatch):
    """Fresh i18n state per test, restored afterwards."""
    monkeypatch.setattr(i18n, "_languages", {})
    monkeypatch.setattr(i18n, "_strings", {})
    monkeypatch.setattr(i18n, "_fallback", {})
    monkeypatch.setattr(i18n, "_current_lang", i18n._DEFAULT_LANG)
    monkeypatch.setattr(i18n, "_on_language_change", [])
    i18n.init()
    return i18n


def test_all_languages_load_with_same_keys(lang):
    assert lang.available_languages() == ["de", "en", "uk"]
    keys = {code: set(d) for code, d in lang._languages.items()}
    assert keys["uk"] == keys["en"] == keys["de"]
    assert len(keys["uk"]) > 100


@pytest.mark.parametrize("code,expected", [
    ("uk", "Надіслати"),
    ("en", "Send"),
    ("de", "Senden"),
])
def test_translation_per_language(lang, code, expected):
    lang.set_language(code, save=False)
    assert expected in lang.t("btn_send")


def test_missing_key_returns_key(lang):
    assert lang.t("no_such_key_xyz") == "no_such_key_xyz"


def test_missing_key_falls_back_to_ukrainian(lang, monkeypatch):
    lang.set_language("en", save=False)
    monkeypatch.delitem(lang._strings, "btn_send")
    assert "Надіслати" in lang.t("btn_send")


def test_format_placeholders(lang):
    lang.set_language("en", save=False)
    assert lang.t("eta_minutes", m=2, s=5) == "2m 05s"


def test_bad_format_args_do_not_raise(lang):
    lang.set_language("en", save=False)
    assert "{" in lang.t("eta_minutes", wrong=1)


def test_unknown_language_is_ignored(lang):
    lang.set_language("en", save=False)
    lang.set_language("xx", save=False)
    assert lang.get_language() == "en"


def test_language_choice_is_persisted(lang):
    lang.set_language("de")
    saved = json.loads(lang._SETTINGS_FILE.read_text(encoding="utf-8"))
    assert saved == {"language": "de"}
    lang.set_language("uk", save=False)
    lang.init()
    assert lang.get_language() == "de"
    lang.set_language("uk")


def test_change_callbacks_are_called(lang):
    seen = []
    lang.on_language_change(seen.append)
    lang.set_language("en", save=False)
    assert seen == ["en"]


# ── Human-readable formatting (gui helpers) ─────────────────────────

@pytest.fixture
def fmt(lang):
    lang.set_language("en", save=False)
    from app import gui
    return gui


@pytest.mark.parametrize("value,expected", [
    (0, "0.0 B"),
    (1023, "1023.0 B"),
    (1024, "1.0 KB"),
    (5 * 1024 ** 3, "5.0 GB"),
])
def test_human_size(fmt, value, expected):
    assert fmt._human_size(value) == expected


@pytest.mark.parametrize("seconds,expected", [
    (5, "5s"),
    (65, "1m 05s"),
    (3725, "1h 02m"),
    (-1, "—"),
    (10 ** 7, "—"),
])
def test_human_eta(fmt, seconds, expected):
    assert fmt._human_eta(seconds) == expected


def test_generated_session_code_format(fmt):
    import re
    codes = {fmt._generate_code() for _ in range(200)}
    assert len(codes) == 200
    assert all(re.fullmatch(r"[a-z0-9]{4}-[a-z0-9]{4}", c) for c in codes)
