#!/usr/bin/env python3
"""
Run the repository's relay server locally (for interop tests and manual
testing with the Android emulator).

    python scripts/local_relay.py            # prints: READY ws://127.0.0.1:<port>
    python scripts/local_relay.py --host 0.0.0.0

The relay stops when stdin is closed or on Ctrl+C. From the Android emulator
the host machine is reachable as 10.0.2.2, i.e. ws://10.0.2.2:<port>.
"""

from __future__ import annotations

import argparse
import logging
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.helpers.local_relay import LocalRelay  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--host", default="127.0.0.1", help="listen address (0.0.0.0 to reach it from other devices)")
    parser.add_argument("--port", type=int, default=0, help="WebSocket port (default: a free one)")
    args = parser.parse_args()
    # the readiness probe opens a bare TCP connection; don't log it as an error
    logging.getLogger("websockets.server").setLevel(logging.CRITICAL)
    relay = LocalRelay(Path(tempfile.mkdtemp(prefix="secureshare-local-relay-")), host=args.host, port=args.port)
    print(f"READY {relay.url}", flush=True)
    try:
        sys.stdin.read()          # returns when the parent closes stdin
    except KeyboardInterrupt:
        pass
    finally:
        relay.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
