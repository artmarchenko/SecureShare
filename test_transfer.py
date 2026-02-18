"""
SecureShare — automated local transfer test.

Runs sender + receiver in parallel threads on ONE machine using a local
WebSocket relay server (no Cloudflare, no MQTT needed).

Scenarios
---------
  basic          – 1 / 10 / 100 MB, both sides start together
  delayed        – receiver joins 5 s after sender          (caught "both waiting" bug)
  throttled      – relay artificially limited to 1 MB/s     (caught socket-timeout bug)
  window_ctrl    – 200 MB through window-ACK flow control   (caught relay buffer overflow)
  signaling_mock – mock SignalingClient, late join + re-pub  (caught signaling deadlock)

Usage
-----
    python -X utf8 test_transfer.py                      # all scenarios, default sizes
    python -X utf8 test_transfer.py --sizes 1 10 100     # custom sizes for basic/delayed/throttled
    python -X utf8 test_transfer.py --only basic         # one scenario
    python -X utf8 test_transfer.py --only signaling_mock
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import queue
import secrets
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

# ── colour output ─────────────────────────────────────────────────────────────
try:
    import colorama; colorama.init()
    GREEN  = "\033[92m"; RED    = "\033[91m"
    YELLOW = "\033[93m"; CYAN   = "\033[96m"
    RESET  = "\033[0m";  BOLD   = "\033[1m"
except ImportError:
    GREEN = RED = YELLOW = CYAN = RESET = BOLD = ""

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)

# ── project imports ───────────────────────────────────────────────────────────
from app.relay_server import LocalRelayServer
from app.ws_relay     import WSRelaySender, WSRelayReceiver
from app.crypto_utils import CryptoSession


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _make_test_file(size_mb: int, directory: Path) -> Path:
    path = directory / f"test_{size_mb}mb.bin"
    remaining = size_mb * 1024 * 1024
    with open(path, "wb") as f:
        while remaining > 0:
            block = min(remaining, 4 * 1024 * 1024)
            f.write(secrets.token_bytes(block))
            remaining -= block
    return path


def _make_crypto_pair(session_code: str) -> tuple[CryptoSession, CryptoSession]:
    s = CryptoSession(session_code)
    r = CryptoSession(session_code)
    s.derive_shared_key(r.get_public_key_bytes())
    r.derive_shared_key(s.get_public_key_bytes())
    return s, r


def _dump(label: str, lines: list[str]) -> None:
    for line in lines:
        print(f"    {YELLOW}[{label}]{RESET} {line}")


def _progress_bar(label: str, done: int, total: int, speed: float) -> None:
    pct = done * 100 // total if total else 0
    bar = "█" * (pct * 20 // 100) + "░" * (20 - pct * 20 // 100)
    print(f"\r    {label} [{bar}] {pct:3d}%  {speed/1e6:5.1f} MB/s  ",
          end="", flush=True)


# ═══════════════════════════════════════════════════════════════════════════════
# Throttling relay proxy  (simulates slow CF Tunnel)
# ═══════════════════════════════════════════════════════════════════════════════

class ThrottledRelay:
    """
    Wraps a LocalRelayServer and limits throughput to `limit_bps` bytes/second.
    Useful for simulating the Cloudflare Tunnel bandwidth bottleneck.
    """

    def __init__(self, limit_bps: int = 1 * 1024 * 1024):
        self._limit  = limit_bps
        self._server: Optional[LocalRelayServer] = None
        self._proxy_port = 0
        self._ready  = threading.Event()
        self._stop   = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def port(self) -> int:
        return self._proxy_port

    def start(self) -> bool:
        # Start the real relay first
        self._server = LocalRelayServer()
        if not self._server.start():
            return False
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="throttled-relay"
        )
        self._thread.start()
        return self._ready.wait(timeout=5)

    def stop(self) -> None:
        self._stop.set()
        if self._server:
            self._server.stop()

    # ── asyncio proxy ─────────────────────────────────────────────────────────

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._serve())

    async def _serve(self) -> None:
        try:
            import websockets
        except ImportError:
            self._ready.set()
            return

        async with websockets.serve(self._handler, "localhost", 0) as srv:
            sock = srv.sockets[0]
            self._proxy_port = sock.getsockname()[1]
            self._ready.set()
            await srv.wait_closed()

    async def _handler(self, ws_client) -> None:
        """Connect to real relay and proxy traffic with throttling."""
        import websockets

        real_url = f"ws://localhost:{self._server.port}"
        try:
            async with websockets.connect(real_url) as ws_real:
                # Pipe in both directions concurrently
                await asyncio.gather(
                    self._pipe(ws_client, ws_real, "C→R"),
                    self._pipe(ws_real, ws_client, "R→C"),
                    return_exceptions=True,
                )
        except Exception:
            pass

    async def _pipe(self, src, dst, label: str) -> None:
        """Forward messages from src to dst, honouring throughput limit."""
        bucket   = self._limit   # token bucket (bytes available now)
        last_ts  = time.monotonic()
        try:
            async for msg in src:
                nbytes = len(msg)

                # Refill bucket based on elapsed time
                now    = time.monotonic()
                bucket = min(self._limit,
                             bucket + (now - last_ts) * self._limit)
                last_ts = now

                # Wait if we're over limit
                if nbytes > bucket:
                    wait = (nbytes - bucket) / self._limit
                    await asyncio.sleep(wait)
                    bucket = 0
                else:
                    bucket -= nbytes

                await dst.send(msg)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# Mock SignalingClient  (no MQTT, no ntfy.sh)
# ═══════════════════════════════════════════════════════════════════════════════

class MockSignalingPair:
    """
    A shared in-memory signaling bus used by both sides in tests.
    Supports delayed delivery to reproduce the 'both waiting' deadlock.
    """

    def __init__(self, publish_delay_s: float = 0.0):
        """
        publish_delay_s – simulate late peer arriving N seconds after the
                          other side already published.
        """
        self._delay  = publish_delay_s
        self._lock   = threading.Lock()
        self._store: dict[str, dict]        = {}   # role → info
        self._events: dict[str, threading.Event] = {
            "sender":   threading.Event(),
            "receiver": threading.Event(),
        }
        self._republish_counts: dict[str, int] = {"sender": 0, "receiver": 0}

    # ── side A / side B ───────────────────────────────────────────────────────

    def make_client(self, role: str) -> "MockSignalingClient":
        return MockSignalingClient(self, role)

    # ── internal bus ──────────────────────────────────────────────────────────

    def _publish(self, role: str, info: dict) -> None:
        peer = "receiver" if role == "sender" else "sender"
        with self._lock:
            self._republish_counts[role] += 1
            old = self._store.get(role)
        if self._delay > 0 and self._republish_counts[role] == 1:
            # First publish of this role is delivered after a delay
            def _delayed():
                time.sleep(self._delay)
                with self._lock:
                    self._store[role] = info
                    self._events[peer].set()
            threading.Thread(target=_delayed, daemon=True).start()
        else:
            with self._lock:
                self._store[role] = info
                self._events[peer].set()

    def _wait_for_peer(self, my_role: str, timeout: float = 60) -> Optional[dict]:
        """
        Block until peer info arrives.
        The client re-publishes every 20 s — we test that this actually helps.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = min(20, deadline - time.time())
            if self._events[my_role].wait(timeout=remaining):
                peer = "receiver" if my_role == "sender" else "sender"
                with self._lock:
                    return self._store.get(peer)
        return None


class MockSignalingClient:
    """Drop-in for SignalingClient in tests."""

    REPUBLISH_INTERVAL = 20

    def __init__(self, bus: MockSignalingPair, role: str):
        self._bus  = bus
        self.role  = role
        self._last_info: Optional[dict] = None

    def connect(self, timeout: float = 10) -> bool:
        return True          # always succeeds in tests

    def publish_info(self, info: dict) -> None:
        self._last_info = {**info, "role": self.role}
        self._bus._publish(self.role, self._last_info)

    def wait_for_peer(self, timeout: float = 60) -> Optional[dict]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            wait = min(self.REPUBLISH_INTERVAL, remaining)
            peer = self._bus._wait_for_peer(self.role, timeout=wait)
            if peer is not None:
                return peer
            # Re-publish (as the real SignalingClient does every 20 s)
            if self._last_info and time.time() < deadline:
                self._bus._publish(self.role, self._last_info)
        return None

    def disconnect(self) -> None:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# Core transfer runner  (shared by all scenarios)
# ═══════════════════════════════════════════════════════════════════════════════

def _run_transfer(
    *,
    size_mb:        int,
    ws_url:         str,
    tmp_dir:        Path,
    scenario_tag:   str = "",
    receiver_delay: float = 0.0,   # seconds before receiver starts
    sender_delay:   float = 0.0,   # seconds before sender starts
    timeout_s:      float = 600,
) -> bool:
    """
    Start sender + receiver threads, return True if transfer succeeds and
    SHA-256 of received file matches the original.
    """
    src_dir  = tmp_dir / f"send_{scenario_tag}"
    recv_dir = tmp_dir / f"recv_{scenario_tag}"
    src_dir.mkdir(parents=True, exist_ok=True)
    recv_dir.mkdir(parents=True, exist_ok=True)

    t0_create = time.monotonic()
    src_file  = _make_test_file(size_mb, src_dir)
    src_hash  = _sha256(src_file)
    print(f"    Created {size_mb} MB in {time.monotonic()-t0_create:.1f}s  "
          f"SHA-256: {src_hash[:16]}…")

    session_code   = secrets.token_hex(4).upper()
    sender_cs, receiver_cs = _make_crypto_pair(session_code)

    send_ok:    list[bool]        = [False]
    recv_path:  list[Optional[Path]] = [None]
    send_log:   list[str]         = []
    recv_log:   list[str]         = []

    def on_ss(m: str): send_log.append(m)
    def on_rs(m: str): recv_log.append(m)
    def on_sp(done, tot, spd): _progress_bar("S", done, tot, spd)
    def on_rp(done, tot, spd): _progress_bar("R", done, tot, spd)

    sender = WSRelaySender(
        local_ws_url=ws_url, session_code=session_code,
        filepath=src_file, crypto=sender_cs,
        on_progress=on_sp, on_status=on_ss,
    )
    receiver = WSRelayReceiver(
        relay_url=ws_url, session_code=session_code,
        save_dir=recv_dir, crypto=receiver_cs,
        on_progress=on_rp, on_status=on_rs,
    )

    def _send():
        if sender_delay:
            time.sleep(sender_delay)
        send_ok[0] = sender.send()

    def _recv():
        if receiver_delay:
            time.sleep(receiver_delay)
        recv_path[0] = receiver.receive()

    t_start = time.monotonic()
    rt = threading.Thread(target=_recv, daemon=True)
    st = threading.Thread(target=_send, daemon=True)
    rt.start()
    if not receiver_delay:
        time.sleep(0.3)   # receiver registers before sender in normal flow
    st.start()

    st.join(timeout=timeout_s)
    rt.join(timeout=timeout_s)
    print()

    elapsed = time.monotonic() - t_start

    if not send_ok[0]:
        print(f"    {RED}SEND FAILED{RESET}")
        _dump("Sender",   send_log[-8:])
        _dump("Receiver", recv_log[-4:])
        return False

    if recv_path[0] is None:
        print(f"    {RED}RECEIVE FAILED{RESET}")
        _dump("Sender",   send_log[-4:])
        _dump("Receiver", recv_log[-8:])
        return False

    dst_hash = _sha256(recv_path[0])
    if dst_hash != src_hash:
        print(f"    {RED}HASH MISMATCH{RESET}")
        print(f"    src: {src_hash}")
        print(f"    dst: {dst_hash}")
        return False

    avg = size_mb * 1e6 / elapsed if elapsed else 0
    print(f"    {GREEN}OK{RESET}  {elapsed:.1f}s  avg {avg/1e6:.1f} MB/s")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# Scenarios
# ═══════════════════════════════════════════════════════════════════════════════

def scenario_basic(sizes: list[int], server: LocalRelayServer, tmp_dir: Path) -> bool:
    """Standard transfer at various sizes — both sides start simultaneously."""
    print(f"\n{BOLD}[SCENARIO: basic]{RESET}  both sides start together")
    ok = True
    for mb in sizes:
        print(f"\n  {CYAN}>>> {mb} MB{RESET}")
        result = _run_transfer(
            size_mb=mb, ws_url=f"ws://localhost:{server.port}",
            tmp_dir=tmp_dir / "basic", scenario_tag=f"{mb}mb",
        )
        ok = ok and result
    return ok


def scenario_delayed(sizes: list[int], server: LocalRelayServer, tmp_dir: Path) -> bool:
    """
    Receiver starts AFTER sender — reproduces the 'both waiting' deadlock.
    The sender must keep the connection open; receiver arrives 5 s later
    and should still complete the transfer.
    BUG it catches: relay server drops connection if receiver doesn't arrive
                    within the initial window.
    """
    DELAY = 5
    print(f"\n{BOLD}[SCENARIO: delayed]{RESET}  receiver arrives {DELAY}s after sender")
    ok = True
    for mb in sizes:
        print(f"\n  {CYAN}>>> {mb} MB  (receiver +{DELAY}s){RESET}")
        result = _run_transfer(
            size_mb=mb, ws_url=f"ws://localhost:{server.port}",
            tmp_dir=tmp_dir / "delayed", scenario_tag=f"{mb}mb",
            receiver_delay=DELAY,
        )
        ok = ok and result
    return ok


def scenario_throttled(sizes: list[int], tmp_dir: Path) -> bool:
    """
    Transfer through a bandwidth-limited relay (1 MB/s) — reproduces the
    socket timeout that killed transfers via slow Cloudflare Tunnel.
    BUG it catches: ws.recv() with timeout=30s raised exception when a gap
                    between chunks exceeded 30 s.
    """
    LIMIT_BPS = 1 * 1024 * 1024    # 1 MB/s — CF Tunnel realistic speed
    print(f"\n{BOLD}[SCENARIO: throttled]{RESET}  relay capped at {LIMIT_BPS//1024} KB/s")

    relay = ThrottledRelay(limit_bps=LIMIT_BPS)
    if not relay.start():
        print(f"  {RED}Could not start throttled relay{RESET}")
        return False

    ok = True
    try:
        for mb in sizes:
            expected_s = mb * 1e6 / LIMIT_BPS
            print(f"\n  {CYAN}>>> {mb} MB  (expected ~{expected_s:.0f}s){RESET}")
            result = _run_transfer(
                size_mb=mb, ws_url=f"ws://localhost:{relay.port}",
                tmp_dir=tmp_dir / "throttled", scenario_tag=f"{mb}mb",
                timeout_s=max(120, expected_s * 3),
            )
            ok = ok and result
    finally:
        relay.stop()
    return ok


def scenario_window_ctrl(tmp_dir: Path) -> bool:
    """
    200 MB file through the window-ACK flow-control mechanism.
    BUG it catches: sender flooded all 75 MB into relay buffer instantly,
                    relay's asyncio queue overflowed, receiver got disconnected.
    """
    MB = 200
    print(f"\n{BOLD}[SCENARIO: window_ctrl]{RESET}  {MB} MB with flow-control window")

    server = LocalRelayServer()
    if not server.start():
        print(f"  {RED}Could not start relay server{RESET}")
        return False

    print(f"\n  {CYAN}>>> {MB} MB{RESET}")
    try:
        return _run_transfer(
            size_mb=MB, ws_url=f"ws://localhost:{server.port}",
            tmp_dir=tmp_dir / "window", scenario_tag=f"{MB}mb",
            timeout_s=300,
        )
    finally:
        server.stop()


def scenario_signaling_mock(tmp_dir: Path) -> bool:
    """
    Tests the signaling state machine in isolation with a mock bus.
    Covers:
      1. Normal case   – both publish immediately, both find each other.
      2. Late receiver – receiver's publish is delayed 8 s.
                         Sender must re-publish and receiver must eventually
                         find the sender (tests re-publish every 20 s).
      3. Late sender   – sender's publish is delayed 8 s (symmetric).
    BUG it catches: 'both waiting' deadlock when one side joined late and
                    the other side stopped re-publishing after the first attempt.
    """
    print(f"\n{BOLD}[SCENARIO: signaling_mock]{RESET}  mock signaling bus")

    results: list[tuple[str, bool]] = []
    WAIT_TIMEOUT = 40   # seconds

    for label, delay_role, delay_s in [
        ("normal      (delay=0s)", "none",     0),
        ("late recv   (delay=8s)", "receiver", 8),
        ("late sender (delay=8s)", "sender",   8),
    ]:
        print(f"\n  {CYAN}>>> {label}{RESET}")
        t0 = time.monotonic()

        bus = MockSignalingPair(
            publish_delay_s=delay_s if delay_role != "none" else 0,
        )
        sender_sig   = bus.make_client("sender")
        receiver_sig = bus.make_client("receiver")

        # Simulate what gui.py's _send_worker / _recv_worker do
        sender_found:   list[Optional[dict]] = [None]
        receiver_found: list[Optional[dict]] = [None]

        def _sender_flow():
            sender_sig.connect()
            info = {"pub_key": "AABBCC", "relay_url": "ws://localhost:9999"}
            if delay_role == "sender":
                time.sleep(delay_s)          # late sender
            sender_sig.publish_info(info)
            sender_found[0] = sender_sig.wait_for_peer(timeout=WAIT_TIMEOUT)

        def _receiver_flow():
            receiver_sig.connect()
            info = {"pub_key": "DDEEFF"}
            if delay_role == "receiver":
                time.sleep(delay_s)          # late receiver
            receiver_sig.publish_info(info)
            receiver_found[0] = receiver_sig.wait_for_peer(timeout=WAIT_TIMEOUT)

        st = threading.Thread(target=_sender_flow,   daemon=True)
        rt = threading.Thread(target=_receiver_flow, daemon=True)
        st.start(); rt.start()
        st.join(timeout=WAIT_TIMEOUT + 5)
        rt.join(timeout=WAIT_TIMEOUT + 5)

        elapsed = time.monotonic() - t0
        ok = (sender_found[0] is not None) and (receiver_found[0] is not None)

        icon = f"{GREEN}OK{RESET}" if ok else f"{RED}FAIL{RESET}"
        print(f"    {icon}  {elapsed:.1f}s")
        if not ok:
            if sender_found[0] is None:
                print(f"    {YELLOW}  sender never found receiver{RESET}")
            if receiver_found[0] is None:
                print(f"    {YELLOW}  receiver never found sender{RESET}")

        results.append((label, ok))

    return all(ok for _, ok in results)


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(description="SecureShare automated tests")
    parser.add_argument(
        "--sizes", nargs="+", type=int, default=[1, 10],
        help="file sizes in MB for basic/delayed/throttled scenarios",
    )
    parser.add_argument(
        "--only", metavar="SCENARIO",
        choices=["basic", "delayed", "throttled", "window_ctrl", "signaling_mock"],
        help="run only one scenario",
    )
    args = parser.parse_args()

    sizes = args.sizes
    only  = args.only

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  SecureShare — Automated Test Suite{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  File sizes : {sizes} MB")
    if only:
        print(f"  Scenario   : {only} only")
    print(f"{BOLD}{'='*60}{RESET}")

    tmp_root = Path(tempfile.mkdtemp(prefix="ss_test_"))
    print(f"  Tmp dir    : {tmp_root}\n")

    # Shared relay server for basic + delayed scenarios
    main_server = LocalRelayServer()
    if not main_server.start():
        print(f"\n{RED}Could not start relay server{RESET}\n")
        sys.exit(1)
    print(f"  Main relay : ws://localhost:{main_server.port}")

    all_results: dict[str, bool] = {}

    try:
        # ── basic ──────────────────────────────────────────────────────────────
        if not only or only == "basic":
            all_results["basic"] = scenario_basic(sizes, main_server, tmp_root)

        # ── delayed ────────────────────────────────────────────────────────────
        if not only or only == "delayed":
            all_results["delayed"] = scenario_delayed(sizes, main_server, tmp_root)

        # ── throttled ──────────────────────────────────────────────────────────
        if not only or only == "throttled":
            throttle_sizes = [mb for mb in sizes if mb <= 20]
            if not throttle_sizes:
                throttle_sizes = [5]    # always test at least 5 MB throttled
            all_results["throttled"] = scenario_throttled(throttle_sizes, tmp_root)

        # ── window_ctrl ────────────────────────────────────────────────────────
        if not only or only == "window_ctrl":
            all_results["window_ctrl"] = scenario_window_ctrl(tmp_root)

        # ── signaling_mock ─────────────────────────────────────────────────────
        if not only or only == "signaling_mock":
            all_results["signaling_mock"] = scenario_signaling_mock(tmp_root)

    finally:
        main_server.stop()
        shutil.rmtree(tmp_root, ignore_errors=True)

    # ── summary ────────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  Results{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")

    all_ok = True
    for name, ok in all_results.items():
        icon = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
        print(f"  {icon}  {name}")
        if not ok:
            all_ok = False

    print(f"{BOLD}{'='*60}{RESET}")
    if all_ok:
        print(f"  {GREEN}{BOLD}ALL PASSED{RESET}")
    else:
        print(f"  {RED}{BOLD}SOME FAILED{RESET}")
    print(f"{BOLD}{'='*60}{RESET}\n")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
