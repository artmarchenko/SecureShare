#!/usr/bin/env python3
"""
Android end-to-end test: the app on an emulator ↔ local relay ↔ desktop client.

Runs mobile/integration_test/app_e2e_test.dart and plays the PC side:
  1. PC sends a file, the app receives it — Home is pressed mid-transfer
     and the app is brought back later (the foreground service keeps it going);
  2. the app sends a file, the PC receives it — the screen is turned off
     mid-transfer.
Checks the files on both ends by SHA-256.

    python scripts/android_e2e.py [--device emulator-5554] [--mb 64]

The relay listens on 127.0.0.1:<port>; the emulator reaches it as 10.0.2.2.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_ID = "io.github.artmarchenko.secureshare"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def tool(name: str) -> str:
    found = shutil.which(name) or shutil.which(name + ".bat") or shutil.which(name + ".exe")
    if found:
        return found
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or \
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk")
    candidate = Path(sdk) / "platform-tools" / (name + (".exe" if os.name == "nt" else ""))
    if candidate.exists():
        return str(candidate)
    sys.exit(f"{name} not found")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--device", default=None, help="adb serial (default: the only device)")
    parser.add_argument("--mb", type=int, default=64, help="file size in MiB for each direction")
    parser.add_argument("--port", type=int, default=18765)
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    if not args.device:  # flutter would otherwise pick the desktop
        out = subprocess.run([tool("adb"), "devices"], capture_output=True, text=True).stdout
        serials = [row.split()[0] for row in out.splitlines()[1:] if row.strip().endswith("device")]
        if len(serials) != 1:
            sys.exit(f"need exactly one Android device, found {serials}; use --device")
        args.device = serials[0]
    adb = [tool("adb"), "-s", args.device]
    flutter = tool("flutter")
    py = sys.executable
    work = Path(tempfile.mkdtemp(prefix="secureshare-e2e-"))
    relay_url = f"ws://127.0.0.1:{args.port}"
    procs: list[subprocess.Popen] = []

    def spawn(cmd: list[str], log: Path, stdin=None) -> subprocess.Popen:
        p = subprocess.Popen(cmd, cwd=ROOT, stdout=open(log, "w", encoding="utf-8"), stderr=subprocess.STDOUT,
                             stdin=stdin, env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"})
        procs.append(p)
        return p

    try:
        spawn([py, "scripts/local_relay.py", "--port", str(args.port)], work / "relay.log",
              stdin=subprocess.PIPE)
        for _ in range(100):
            if "READY" in (work / "relay.log").read_text(encoding="utf-8", errors="replace"):
                break
            time.sleep(0.1)
        else:
            sys.exit("relay did not start")

        # PC → phone: the PC sender waits for the app
        to_phone = work / "to-phone.bin"
        to_phone.write_bytes(os.urandom(args.mb << 20))
        recv_code, send_code = "e2er-0001", "e2es-0001"
        pc_sender = None  # started when the app is up (the build can take longer than it waits)
        inbox = work / "pc-inbox"
        inbox.mkdir()
        pc_receiver = None  # started when the app starts sending (it gives up after 5 min of waiting)

        cmd = [flutter, "test", "integration_test/app_e2e_test.dart", "--reporter", "expanded",
               f"--dart-define=RELAY_URL=ws://10.0.2.2:{args.port}",
               f"--dart-define=E2E_RECV_CODE={recv_code}", f"--dart-define=E2E_RECV_SHA={sha256(to_phone)}",
               f"--dart-define=E2E_SEND_CODE={send_code}", f"--dart-define=E2E_SEND_MB={args.mb}"]
        cmd += ["-d", args.device]
        print("$", " ".join(cmd[1:]), flush=True)
        test = subprocess.Popen(cmd, cwd=ROOT / "mobile", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace")
        procs.append(test)

        # Android ≤ 10 asks for the storage permission; a test can't tap the system
        # dialog, so grant it as soon as the app is installed (fails harmlessly on 11+)
        def grant_storage() -> None:
            while test.poll() is None:
                r = subprocess.run(adb + ["shell", "pm", "grant", APP_ID, "android.permission.WRITE_EXTERNAL_STORAGE"],
                                   capture_output=True, text=True)
                out = r.stdout + r.stderr
                if r.returncode == 0 or "not a changeable permission" in out or "has not requested" in out:
                    return
                time.sleep(0.5)
        threading.Thread(target=grant_storage, daemon=True).start()

        def later(delay: float, *adb_args: str) -> None:
            threading.Timer(delay, lambda: subprocess.run(adb + list(adb_args), capture_output=True)).start()

        sent_sha = None
        transferring = 0
        for line in test.stdout:
            print(line, end="", flush=True)
            if "E2E:RECEIVE_START" in line:
                pc_sender = spawn([py, "-m", "app.cli", "--relay", relay_url, "--yes", "send", str(to_phone),
                                   "--code", recv_code], work / "pc_sender.log")
            elif "E2E:TRANSFERRING" in line:
                transferring += 1
                if transferring == 1:   # receiving: leave the app, come back later
                    print(">>> Home, back in 8 s", flush=True)
                    later(2, "shell", "input", "keyevent", "KEYCODE_HOME")
                    later(10, "shell", "am", "start", "-n", f"{APP_ID}/.MainActivity")
                else:                   # sending: screen off, on again later
                    print(">>> screen off, on in 8 s", flush=True)
                    later(2, "shell", "input", "keyevent", "KEYCODE_SLEEP")
                    later(10, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
            elif "E2E:SENT_SHA" in line:
                sent_sha = line.split("E2E:SENT_SHA", 1)[1].strip()
                pc_receiver = spawn([py, "-m", "app.cli", "--relay", relay_url, "--yes", "receive", send_code,
                                     "--out", str(inbox)], work / "pc_receiver.log")
        code = test.wait()

        problems = []
        if code != 0:
            problems.append(f"flutter test exited with {code}")
        for name, proc in (("PC sender", pc_sender), ("PC receiver", pc_receiver)):
            if proc is None:
                problems.append(f"{name} was never started")
                continue
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                problems.append(f"{name} did not finish")
        got = inbox / "from-phone.bin"
        if not got.exists():
            problems.append("PC did not receive from-phone.bin")
        elif sent_sha and sha256(got) != sent_sha:
            problems.append("from-phone.bin differs on the PC")
        if problems:
            for log in sorted(work.glob("*.log")):
                print(f"\n----- {log.name} -----\n" + log.read_text(encoding="utf-8", errors="replace")[-3000:])
            print("\nFAILED: " + "; ".join(problems))
            return 1
        print(f"\nOK: PC → phone and phone → PC ({args.mb} MiB each), files identical")
        return 0
    finally:
        for p in procs:
            if p.poll() is None:
                if p.stdin:
                    p.stdin.close()
                p.kill()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
