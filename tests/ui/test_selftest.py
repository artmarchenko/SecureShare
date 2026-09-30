"""The packaging smoke test used by CI after PyInstaller."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_selftest_passes_from_source(app):
    from app import selftest
    assert selftest.run() == 0


def test_selftest_detects_missing_language(app, monkeypatch):
    from app import i18n, selftest
    monkeypatch.setitem(i18n._languages, "de", {})
    monkeypatch.setattr(i18n, "available_languages", lambda: ["en", "uk"])
    assert selftest.run() == 1


def test_main_self_test_flag_exits_zero(tmp_path):
    env = {"APPDATA": str(tmp_path)}
    import os
    env = {**os.environ, **env}
    proc = subprocess.run([sys.executable, str(ROOT / "main.py"), "--self-test"],
                          cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Self-test OK" in proc.stdout + proc.stderr
