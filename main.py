"""
SecureShare — peer-to-peer encrypted file sharing.

Run:  python main.py
"""

import logging
import sys

# Configure logging before importing app modules
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

from app.gui import App


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
