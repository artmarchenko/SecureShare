"""
SecureShare — command-line client (no GUI).

    python -m app.cli send <file> [--code CODE] [--relay URL] [--yes] [--lang en]
    python -m app.cli receive <code> [--out DIR] [--relay URL] [--yes] [--lang en]

Uses exactly the same transfer code as the desktop app. Handy for testing
other implementations (e.g. the Android app against the PC), for scripts,
and for headless machines.

The first line the sender prints is `CODE: xxxx-xxxx`. Verification codes
are shown and must be confirmed (y/N) unless --yes is given — only use
--yes when you trust the channel (tests, your own two machines).

Exit codes: 0 success, 1 transfer failed or rejected, 2 usage error,
130 interrupted.
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
import time
from pathlib import Path

from . import i18n, ws_relay
from .crypto_utils import new_session_code
from .format import human_size, human_speed


def _confirm(code: str, assume_yes: bool, out) -> bool:
    print(f"VERIFY: {code}", file=out, flush=True)
    if assume_yes:
        return True
    try:
        answer = input("Does the other side show the same code? [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes", "т", "так", "j", "ja")


class _Progress:
    def __init__(self, err) -> None:
        self._err = err
        self._last = 0.0

    def __call__(self, done: int, total: int, speed: float) -> None:
        now = time.monotonic()
        if now - self._last < 1.0 and done < total:
            return
        self._last = now
        pct = done / total * 100 if total else 0
        print(f"  {pct:5.1f}%  {human_size(done)} / {human_size(total)}  {human_speed(speed)}",
              file=self._err, flush=True)


def _run(peer, action) -> int:
    result: list = []
    worker = threading.Thread(target=lambda: result.append(action()), daemon=True)
    worker.start()
    try:
        while worker.is_alive():
            worker.join(0.2)
    except KeyboardInterrupt:
        peer.cancel()
        worker.join(10)
        return 130
    return 0 if result and result[0] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="SecureShare command-line client")
    parser.add_argument("--relay", help="relay URL (default: the public relay)")
    parser.add_argument("--yes", action="store_true", help="confirm the verification code automatically")
    parser.add_argument("--lang", default="en", choices=["uk", "en", "de"], help="language of status messages")
    parser.add_argument("--quiet", action="store_true", help="only print CODE/VERIFY/RESULT lines")
    sub = parser.add_subparsers(dest="command", required=True)
    p_send = sub.add_parser("send", help="send a file")
    p_send.add_argument("file", type=Path)
    p_send.add_argument("--code", help="session code to use (default: random)")
    p_recv = sub.add_parser("receive", help="receive a file")
    p_recv.add_argument("code")
    p_recv.add_argument("--out", type=Path, default=Path.cwd(), help="folder to save into (default: current)")
    args = parser.parse_args(argv)

    out, err = sys.stdout, sys.stderr
    logging.basicConfig(level=logging.WARNING, stream=err, format="%(levelname)s %(message)s")
    i18n.init()
    i18n.set_language(args.lang, save=False)
    if args.relay:
        ws_relay.VPS_RELAY_URL = args.relay

    def status(msg: str) -> None:
        if not args.quiet:
            print(msg, file=err, flush=True)
    progress = None if args.quiet else _Progress(err)

    if args.command == "send":
        if not args.file.is_file():
            print(f"not a file: {args.file}", file=err)
            return 2
        code = (args.code or new_session_code()).strip().lower()
        print(f"CODE: {code}", file=out, flush=True)
        peer = ws_relay.VPSRelaySender(code, args.file, on_progress=progress, on_status=status,
                                       on_verify=lambda c: _confirm(c, args.yes, out))
        rc = _run(peer, peer.send)
        print(f"RESULT: {'sent' if rc == 0 else 'failed'}", file=out, flush=True)
        return rc

    if not args.out.is_dir():
        print(f"not a folder: {args.out}", file=err)
        return 2
    holder: list = []
    peer = ws_relay.VPSRelayReceiver(args.code.strip().lower(), args.out, on_progress=progress,
                                     on_status=status, on_verify=lambda c: _confirm(c, args.yes, out))

    def receive():
        holder.append(peer.receive())
        return holder[-1]
    rc = _run(peer, receive)
    print(f"RESULT: {holder[0] if rc == 0 and holder else 'failed'}", file=out, flush=True)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
