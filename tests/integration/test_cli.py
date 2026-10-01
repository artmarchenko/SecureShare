"""The command-line client (python -m app.cli) against the local relay."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _cli(args, relay, tmp_path, stdin=None):
    env = {**os.environ, "APPDATA": str(tmp_path / "appdata"), "PYTHONIOENCODING": "utf-8"}
    return subprocess.Popen(
        [sys.executable, "-m", "app.cli", "--relay", relay.url, *args],
        cwd=ROOT, env=env, text=True, encoding="utf-8",
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def test_cli_send_and_receive(local_relay, tmp_path):
    src = tmp_path / "doc.bin"
    src.write_bytes(os.urandom(700_000))
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    sender = _cli(["--yes", "--quiet", "send", str(src), "--code", "cli1-test"], local_relay, tmp_path)
    receiver = _cli(["--yes", "--quiet", "receive", "CLI1-TEST", "--out", str(inbox)], local_relay, tmp_path)
    s_out, s_err = sender.communicate(timeout=120)
    r_out, r_err = receiver.communicate(timeout=120)
    assert sender.returncode == 0, s_err
    assert receiver.returncode == 0, r_err
    assert s_out.splitlines()[0] == "CODE: cli1-test"
    s_codes = [line for line in s_out.splitlines() if line.startswith("VERIFY:")]
    r_codes = [line for line in r_out.splitlines() if line.startswith("VERIFY:")]
    assert s_codes == r_codes and len(s_codes) == 1
    assert (inbox / "doc.bin").read_bytes() == src.read_bytes()
    assert r_out.strip().endswith(str(inbox / "doc.bin"))


def test_cli_receiver_rejects_code(local_relay, tmp_path):
    src = tmp_path / "x.bin"
    src.write_bytes(b"secret")
    sender = _cli(["--yes", "--quiet", "send", str(src), "--code", "cli2-test"], local_relay, tmp_path)
    receiver = _cli(["--quiet", "receive", "cli2-test", "--out", str(tmp_path)], local_relay, tmp_path)
    r_out, _ = receiver.communicate(input="n\n", timeout=120)
    s_out, _ = sender.communicate(timeout=120)
    assert receiver.returncode == 1 and sender.returncode == 1
    assert "RESULT: failed" in r_out and "RESULT: failed" in s_out


def test_cli_usage_errors(local_relay, tmp_path):
    p = _cli(["send", str(tmp_path / "missing.bin")], local_relay, tmp_path)
    _, err = p.communicate(timeout=60)
    assert p.returncode == 2 and "not a file" in err
