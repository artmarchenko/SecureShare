#!/usr/bin/env python3
"""
Cross-module regression guard for SecureShare.

Purpose:
- Catch accidental regressions across app/server/web before push.
- Validate critical invariants that have broken before.

Run:
    python scripts/regression_guard.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(rel_path: str) -> str:
    path = ROOT / rel_path
    return path.read_text(encoding="utf-8")


def _find(pattern: str, text: str, label: str) -> str:
    m = re.search(pattern, text, flags=re.MULTILINE)
    if not m:
        raise AssertionError(f"{label}: pattern not found: {pattern}")
    return m.group(1)


def _extract_object_block(js_text: str, lang: str) -> str:
    m = re.search(rf"\b{re.escape(lang)}\s*:\s*\{{", js_text)
    if not m:
        raise AssertionError(f"i18n: language block '{lang}' not found")

    i = m.end() - 1  # points to '{'
    depth = 0
    in_string = False
    quote = ""
    escaped = False
    start = i

    while i < len(js_text):
        ch = js_text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                in_string = False
        else:
            if ch in ("'", '"'):
                in_string = True
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return js_text[start + 1 : i]
        i += 1

    raise AssertionError(f"i18n: unterminated language block '{lang}'")


def _extract_i18n_keys_from_index(index_html: str) -> set[str]:
    return set(re.findall(r'data-i18n="([a-zA-Z0-9_]+)"', index_html))


def _extract_keys_from_lang_block(block: str) -> set[str]:
    return set(re.findall(r"^\s*([a-zA-Z0-9_]+)\s*:", block, flags=re.MULTILINE))


def check_version_sync() -> None:
    config = _read("app/config.py")
    relay = _read("server/relay_server.py")
    version_info = _read("version_info.txt")

    app_version = _find(r'APP_VERSION\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', config, "app/config.py")
    latest_version = _find(
        r'LATEST_CLIENT_VERSION\s*=\s*os\.getenv\(\s*"RELAY_LATEST_VERSION"\s*,\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*\)',
        relay,
        "server/relay_server.py",
    )
    filevers = _find(r"filevers=\((\d+,\s*\d+,\s*\d+),\s*0\)", version_info, "version_info.txt")
    version_info_version = ".".join(part.strip() for part in filevers.split(","))

    if len({app_version, latest_version, version_info_version}) != 1:
        raise AssertionError(
            "Version mismatch: "
            f"APP_VERSION={app_version}, "
            f"LATEST_CLIENT_VERSION={latest_version}, "
            f"version_info={version_info_version}"
        )


def check_server_invariants() -> None:
    relay = _read("server/relay_server.py")
    analytics = _read("server/analytics.py")

    if "_get_active_rooms" not in relay:
        raise AssertionError("server/relay_server.py: live active rooms callback is missing")
    if '"active_rooms": max(0, active_rooms)' not in relay:
        raise AssertionError("server/relay_server.py: /health active_rooms non-negative guard is missing")

    has_restore_call = ("self._load_from_disk()" in analytics) or ("self._restore_from_latest_snapshot()" in analytics)
    has_restore_impl = ("def _load_from_disk" in analytics) or ("def _restore_from_latest_snapshot" in analytics)
    if not (has_restore_call and has_restore_impl):
        raise AssertionError("server/analytics.py: stats restore-on-startup guard is missing")


def check_web_i18n_invariants() -> None:
    index_html = _read("server/www/index.html")
    i18n_js = _read("server/www/i18n.js")

    for marker in (
        'data-lang="uk"',
        'data-lang="en"',
        'data-lang="de"',
        'id="btnUk"',
        'id="btnEn"',
        'id="btnDe"',
    ):
        if marker not in index_html:
            raise AssertionError(f"server/www/index.html: missing language control marker '{marker}'")

    for marker in (
        "setLang('uk')",
        "setLang('en')",
        "setLang('de')",
    ):
        if marker not in i18n_js:
            raise AssertionError(f"server/www/i18n.js: missing language handler '{marker}'")

    index_keys = _extract_i18n_keys_from_index(index_html)
    if not index_keys:
        raise AssertionError("server/www/index.html: no data-i18n keys found")

    en_block = _extract_object_block(i18n_js, "en")
    de_block = _extract_object_block(i18n_js, "de")
    en_keys = _extract_keys_from_lang_block(en_block)
    de_keys = _extract_keys_from_lang_block(de_block)

    missing_en = sorted(index_keys - en_keys)
    missing_de = sorted(index_keys - de_keys)
    if missing_en:
        raise AssertionError(f"server/www/i18n.js: EN missing keys used in index.html: {missing_en[:10]}")
    if missing_de:
        raise AssertionError(f"server/www/i18n.js: DE missing keys used in index.html: {missing_de[:10]}")


def main() -> int:
    checks = [
        ("version-sync", check_version_sync),
        ("server-invariants", check_server_invariants),
        ("web-i18n-invariants", check_web_i18n_invariants),
    ]

    failed = []
    for name, check in checks:
        try:
            check()
            print(f"[OK] {name}")
        except Exception as exc:
            failed.append((name, str(exc)))
            print(f"[FAIL] {name}: {exc}")

    if failed:
        print(f"\nRegression guard failed: {len(failed)} check(s).")
        return 1

    print("\nRegression guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
