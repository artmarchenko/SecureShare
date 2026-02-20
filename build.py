"""
Build SecureShare using PyInstaller.

Run:  python build.py

Automatically selects the correct .spec for the current OS:
  - Windows → SecureShare.spec  (produces SecureShare.exe)
  - Linux   → SecureShare-linux.spec  (produces SecureShare)
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
IS_WINDOWS = sys.platform == "win32"


def main():
    if IS_WINDOWS:
        spec_file = ROOT / "SecureShare.spec"
        output_name = "SecureShare.exe"
    else:
        spec_file = ROOT / "SecureShare-linux.spec"
        output_name = "SecureShare"

    if not spec_file.exists():
        print(f"[ERROR] Spec file not found: {spec_file}")
        sys.exit(1)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        str(spec_file),
    ]
    print(f"Platform: {'Windows' if IS_WINDOWS else 'Linux'}")
    print("Running:", " ".join(cmd))
    subprocess.check_call(cmd, cwd=str(ROOT))

    out_path = ROOT / "dist" / output_name
    if out_path.exists():
        size_mb = out_path.stat().st_size / (1024 * 1024)
        print(f"\n[OK] Build complete! {out_path}  ({size_mb:.1f} MB)")
    else:
        print(f"\n[ERROR] Build failed — {output_name} not found")
        sys.exit(1)


if __name__ == "__main__":
    main()
