"""
SecureShare — peer-to-peer encrypted file sharing.

Run:  python main.py          (with console)
      pythonw main.py         (no console, logs go to file only)
"""

import logging
import os
import sys
from pathlib import Path

# ── Log file path ─────────────────────────────────────────────────
# Logs are always written to a file so they can be inspected
# even when launched without a console (pythonw / .exe).
_LOG_DIR = Path(os.environ.get("APPDATA", Path.home())) / "SecureShare"
_LOG_DIR.mkdir(parents=True, exist_ok=True)
_LOG_FILE = _LOG_DIR / "secureshare.log"

# ── Configure logging ────────────────────────────────────────────
_fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_handlers: list[logging.Handler] = [
    # Always log to file (append, UTF-8)
    logging.FileHandler(_LOG_FILE, encoding="utf-8"),
]

# Add console handler only when stdout is available (python, not pythonw)
if sys.stdout is not None and hasattr(sys.stdout, "write"):
    _handlers.append(logging.StreamHandler(sys.stdout))

logging.basicConfig(
    level=logging.INFO,
    format=_fmt,
    handlers=_handlers,
)

log = logging.getLogger("secureshare")
log.info("Log file: %s", _LOG_FILE)

from app.gui import App


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
