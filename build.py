"""
Build SecureShare into a single .exe using PyInstaller.

Run:  python build.py
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent


def main():
    spec_file = ROOT / "SecureShare.spec"
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        str(spec_file),
    ]
    print("Running:", " ".join(cmd))
    subprocess.check_call(cmd, cwd=str(ROOT))

    exe_path = ROOT / "dist" / "SecureShare.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n[OK] Build complete! {exe_path}  ({size_mb:.1f} MB)")
    else:
        print("\n[ERROR] Build failed — .exe not found")
        sys.exit(1)


if __name__ == "__main__":
    main()
