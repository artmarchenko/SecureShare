"""
Build SecureShare into a single .exe using PyInstaller.

Run:  python build.py
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent


def main():
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name", "SecureShare",
        "--hidden-import", "paho.mqtt.client",
        "--hidden-import", "paho.mqtt",
        "--hidden-import", "customtkinter",
        "--collect-all", "customtkinter",
        str(ROOT / "main.py"),
    ]
    print("Running:", " ".join(cmd))
    subprocess.check_call(cmd, cwd=str(ROOT))

    exe_path = ROOT / "dist" / "SecureShare.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n[OK] Build complete! {exe_path}  ({size_mb:.1f} MB)")
    else:
        print("\n[OK] Build complete! Check dist/ folder")


if __name__ == "__main__":
    main()
