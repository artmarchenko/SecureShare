#!/usr/bin/env python3
"""
Smoke test of a built APK on a device/emulator: install, start with
`--ez selftest true`, wait for "SECURESHARE_SELFTEST OK <version>" in logcat.

    python scripts/android_selftest.py path/to/SecureShare.apk [--version 1.0.0] [--device emulator-5554]

The app checks scrypt via the native code against the protocol vectors, key
exchange + AES-GCM, translations and the receive folder (lib/app/selftest.dart).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time

APP_ID = "io.github.artmarchenko.secureshare"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("apk")
    parser.add_argument("--version", help="expected app version")
    parser.add_argument("--device")
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()

    adb = [shutil.which("adb") or "adb"] + (["-s", args.device] if args.device else [])

    def run(*a: str, check: bool = True) -> str:
        r = subprocess.run(adb + list(a), capture_output=True, text=True, encoding="utf-8", errors="replace")
        if check and r.returncode != 0:
            sys.exit(f"adb {' '.join(a)} failed: {r.stdout}{r.stderr}")
        return r.stdout

    run("uninstall", APP_ID, check=False)   # a build signed with another key can't be installed over
    print(run("install", "-r", args.apk).strip().splitlines()[-1])
    run("logcat", "-c")
    run("shell", "am", "start", "-W", "-n", f"{APP_ID}/.MainActivity", "--ez", "selftest", "true")

    deadline = time.time() + args.timeout
    line = None
    while time.time() < deadline and line is None:
        log = run("logcat", "-d", "-v", "brief")
        for row in log.splitlines():
            if "FATAL EXCEPTION" in row or "Fatal signal" in row:
                print(log[-4000:])
                sys.exit("FAILED: the app crashed")
            if "SECURESHARE_SELFTEST" in row:
                line = row.split("SECURESHARE_SELFTEST", 1)[1].strip()
        time.sleep(1)
    if line is None:
        print(run("logcat", "-d", "-v", "brief")[-4000:])
        sys.exit("FAILED: no self-test result in logcat")
    print(f"self-test: {line}")
    if not line.startswith("OK"):
        return 1
    if args.version and line.split()[-1] != args.version:
        sys.exit(f"FAILED: app reports version {line.split()[-1]}, expected {args.version}")
    if not run("shell", "pidof", APP_ID, check=False).strip():
        sys.exit("FAILED: the app is not running after the self-test")
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
