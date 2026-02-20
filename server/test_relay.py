"""
SecureShare Relay Server — comprehensive test suite.

Usage:
    python test_relay.py                          # test against VPS
    python test_relay.py --url ws://localhost:8765 # test against local
    python test_relay.py --only basic             # run single test
    python test_relay.py --list                   # list all tests

Tests cover: functionality, security, reliability, performance.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import string
import sys
import threading
import time
from dataclasses import dataclass
from typing import Optional

import socket
from urllib.parse import urlparse

try:
    import websocket
except ImportError:
    print("pip install websocket-client")
    sys.exit(1)

# ── Config ──────────────────────────────────────────────────────────

DEFAULT_URL = "wss://secureshare-relay.duckdns.org"
TIMEOUT = 30  # longer timeout for resilience
DNS_RETRIES = 3  # retry DNS resolution before giving up


# ── Helpers ─────────────────────────────────────────────────────────

def random_code(n=16) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def random_bytes(size: int) -> bytes:
    return os.urandom(size)


def _resolve_host(hostname: str, retries: int = DNS_RETRIES) -> None:
    """Pre-resolve DNS with retries to handle transient failures."""
    for attempt in range(retries):
        try:
            socket.getaddrinfo(hostname, None, socket.AF_INET)
            return
        except socket.gaierror:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
    raise socket.gaierror(f"DNS resolution failed for {hostname} after {retries} attempts")


def connect(url: str, timeout: float = TIMEOUT) -> websocket.WebSocket:
    """Connect with DNS retry to handle transient DuckDNS failures."""
    hostname = urlparse(url).hostname
    if hostname:
        _resolve_host(hostname)
    return websocket.create_connection(url, timeout=timeout)


@dataclass
class TestResult:
    name: str
    passed: bool
    duration: float = 0.0
    error: str = ""
    details: str = ""


def _run_pair(url: str, code: str, msg: bytes, send_delay: float = 2.0,
              recv_delay: float = 0.0) -> tuple[Optional[bytes], list[str]]:
    """Helper: run a sender+receiver pair. Returns (received_data, errors)."""
    received = [None]
    errors = []

    def sender():
        try:
            ws = connect(url)
            ws.send(code)
            time.sleep(send_delay)
            ws.send_binary(msg)
            time.sleep(0.5)
            ws.close()
        except Exception as e:
            errors.append(f"sender: {e}")

    def receiver():
        try:
            time.sleep(recv_delay)
            ws = connect(url)
            ws.send(code)
            data = ws.recv()
            if isinstance(data, bytes) and len(data) > 0:
                received[0] = data
            elif isinstance(data, str) and len(data) > 0:
                received[0] = data.encode()
            # Empty data means server closed connection — don't treat as received
            ws.close()
        except Exception as e:
            errors.append(f"receiver: {e}")

    t1 = threading.Thread(target=sender)
    t2 = threading.Thread(target=receiver)
    t1.start(); t2.start()
    t1.join(TIMEOUT); t2.join(TIMEOUT)

    return received[0], errors


# ── Test runner ─────────────────────────────────────────────────────

class RelayTester:
    def __init__(self, url: str):
        self.url = url
        self.results: list[TestResult] = []

    def run_all(self, only: Optional[str] = None) -> list[TestResult]:
        tests = [
            # Functional
            ("1.1_basic_relay", self.test_basic_relay),
            ("1.2_bidirectional", self.test_bidirectional),
            ("1.3_binary_1mb", self.test_binary_1mb),
            ("1.4_multiple_rooms", self.test_multiple_rooms),
            ("1.5_session_isolation", self.test_session_isolation),
            ("1.6_delayed_peer", self.test_delayed_peer),
            ("1.7_disconnect_cleanup", self.test_disconnect_cleanup),
            # Security
            ("2.1_tls", self.test_tls),
            ("2.2_room_full", self.test_room_full),
            ("2.3_no_session_code", self.test_no_session_code),
            # Reliability
            ("3.1_sudden_disconnect", self.test_sudden_disconnect),
            ("3.2_reconnect_same_code", self.test_reconnect_same_code),
            # Performance
            ("4.1_throughput", self.test_throughput),
            ("4.2_latency", self.test_latency),
            ("4.3_concurrent_rooms", self.test_concurrent_rooms),
        ]

        if only:
            tests = [(n, t) for n, t in tests if only in n]
            if not tests:
                print(f"No test matching '{only}'")
                return []

        print(f"\n{'='*60}")
        print(f"  SecureShare Relay Server Test Suite")
        print(f"  Target: {self.url}")
        print(f"{'='*60}\n")

        for name, test_fn in tests:
            print(f"  ▶ {name} ... ", end="", flush=True)
            t0 = time.time()
            try:
                result = test_fn()
                result.duration = time.time() - t0
                if result.passed:
                    detail = f" ({result.details})" if result.details else ""
                    print(f"✅ PASS ({result.duration:.2f}s){detail}")
                else:
                    print(f"❌ FAIL: {result.error}")
            except Exception as e:
                result = TestResult(name=name, passed=False, error=str(e), duration=time.time() - t0)
                print(f"💥 ERROR: {e}")
            self.results.append(result)
            time.sleep(0.5)  # gap between tests

        # Summary
        passed = sum(1 for r in self.results if r.passed)
        total = len(self.results)
        print(f"\n{'='*60}")
        print(f"  Results: {passed}/{total} passed")
        if passed == total:
            print("  🎉 ALL TESTS PASSED!")
        else:
            print("  Failed tests:")
            for r in self.results:
                if not r.passed:
                    print(f"    ❌ {r.name}: {r.error}")
        print(f"{'='*60}\n")

        return self.results

    # ── 1. Functional Tests ──────────────────────────────────────────

    def test_basic_relay(self) -> TestResult:
        """Two clients connect, sender sends, receiver receives."""
        code = random_code()
        msg = b"Hello from basic relay test!"
        data, errors = _run_pair(self.url, code, msg)

        if errors:
            return TestResult("basic_relay", False, error="; ".join(errors))
        if data == msg:
            return TestResult("basic_relay", True)
        return TestResult("basic_relay", False, error=f"Expected {msg!r}, got {data!r}")

    def test_bidirectional(self) -> TestResult:
        """Both clients send and receive simultaneously."""
        code = random_code()
        results_a = []
        results_b = []
        errors = []
        msg_a = b"From A to B bidirectional"
        msg_b = b"From B to A bidirectional"

        def client_a():
            try:
                ws = connect(self.url)
                ws.send(code)
                time.sleep(2)
                ws.send_binary(msg_a)
                data = ws.recv()
                if isinstance(data, bytes) and len(data) > 0:
                    results_a.append(data)
                elif isinstance(data, str) and data:
                    results_a.append(data.encode())
                ws.close()
            except Exception as e:
                errors.append(f"client_a: {e}")

        def client_b():
            try:
                ws = connect(self.url)
                ws.send(code)
                time.sleep(2.5)
                ws.send_binary(msg_b)
                data = ws.recv()
                if isinstance(data, bytes) and len(data) > 0:
                    results_b.append(data)
                elif isinstance(data, str) and data:
                    results_b.append(data.encode())
                ws.close()
            except Exception as e:
                errors.append(f"client_b: {e}")

        t1 = threading.Thread(target=client_a)
        t2 = threading.Thread(target=client_b)
        t1.start(); t2.start()
        t1.join(TIMEOUT); t2.join(TIMEOUT)

        if errors:
            return TestResult("bidirectional", False, error="; ".join(errors))
        ok = (results_a == [msg_b] and results_b == [msg_a])
        if ok:
            return TestResult("bidirectional", True)
        return TestResult("bidirectional", False, error=f"A got {results_a}, B got {results_b}")

    def test_binary_1mb(self) -> TestResult:
        """Send 1 MB of random binary data and verify integrity."""
        code = random_code()
        data_1mb = random_bytes(1 * 1024 * 1024)
        expected_hash = hashlib.sha256(data_1mb).hexdigest()

        data, errors = _run_pair(self.url, code, data_1mb, send_delay=2)
        if errors:
            return TestResult("binary_1mb", False, error="; ".join(errors))
        if data and hashlib.sha256(data).hexdigest() == expected_hash:
            return TestResult("binary_1mb", True, details="1 MB SHA-256 match")
        return TestResult("binary_1mb", False, error=f"Hash mismatch")

    def test_multiple_rooms(self) -> TestResult:
        """5 pairs of clients in separate rooms simultaneously."""
        n_rooms = 5
        successes = [False] * n_rooms

        def pair(idx):
            code = random_code()
            msg = f"Room {idx} data".encode()
            data, errors = _run_pair(self.url, code, msg, send_delay=2)
            successes[idx] = (data == msg and not errors)

        threads = [threading.Thread(target=pair, args=(i,)) for i in range(n_rooms)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(TIMEOUT * 2)

        passed = sum(successes)
        if passed == n_rooms:
            return TestResult("multiple_rooms", True, details=f"{n_rooms}/{n_rooms} rooms OK")
        return TestResult("multiple_rooms", False, error=f"Only {passed}/{n_rooms} rooms succeeded")

    def test_session_isolation(self) -> TestResult:
        """Data from room A doesn't leak to room B."""
        code_a = random_code()
        code_b = random_code()
        msg_a = b"SECRET_A_DATA"
        msg_b = b"SECRET_B_DATA"

        data_a, err_a = _run_pair(self.url, code_a, msg_a, send_delay=2)
        data_b, err_b = _run_pair(self.url, code_b, msg_b, send_delay=2)

        if err_a or err_b:
            return TestResult("session_isolation", False, error=f"errors: a={err_a}, b={err_b}")
        if data_a == msg_a and data_b == msg_b:
            return TestResult("session_isolation", True)
        return TestResult("session_isolation", False, error=f"A={data_a!r}, B={data_b!r}")

    def test_delayed_peer(self) -> TestResult:
        """Sender connects, receiver joins 3s later — should still pair."""
        code = random_code()
        msg = b"Delayed peer test data"
        data, errors = _run_pair(self.url, code, msg, send_delay=5, recv_delay=3)

        if errors:
            return TestResult("delayed_peer", False, error="; ".join(errors))
        if data == msg:
            return TestResult("delayed_peer", True, details="3s delay OK")
        return TestResult("delayed_peer", False, error=f"Got {data!r}")

    def test_disconnect_cleanup(self) -> TestResult:
        """After disconnect, room should be cleaned up and reusable."""
        code = random_code()

        # First: connect and disconnect (no peer)
        try:
            ws1 = connect(self.url)
            ws1.send(code)
            time.sleep(0.5)
            ws1.close()
        except Exception:
            pass

        time.sleep(2)

        # Second: should be able to create a new room with same code
        msg = b"After cleanup test"
        data, errors = _run_pair(self.url, code, msg, send_delay=2)

        if errors:
            return TestResult("disconnect_cleanup", False, error="; ".join(errors))
        if data == msg:
            return TestResult("disconnect_cleanup", True)
        return TestResult("disconnect_cleanup", False, error=f"Got {data!r}")

    # ── 2. Security Tests ────────────────────────────────────────────

    def test_tls(self) -> TestResult:
        """Verify TLS/WSS connection works with valid certificate."""
        if not self.url.startswith("wss://"):
            return TestResult("tls", True, details="Skipped (not WSS)")

        try:
            import ssl
            ws = websocket.create_connection(
                self.url, timeout=10,
                sslopt={"cert_reqs": ssl.CERT_REQUIRED},
            )
            ws.send(random_code())
            time.sleep(0.5)
            ws.close()
            return TestResult("tls", True, details="Certificate valid")
        except ssl.SSLCertVerificationError as e:
            return TestResult("tls", False, error=f"SSL cert invalid: {e}")
        except Exception as e:
            return TestResult("tls", False, error=str(e))

    def test_room_full(self) -> TestResult:
        """Third client connecting WHILE room is active should be rejected."""
        code = random_code()
        third_result = [None]  # "rejected", "timeout", "paired"
        errors = []

        # Client A and B pair and stay connected for 8 seconds
        def client_a():
            try:
                ws = connect(self.url)
                ws.send(code)
                time.sleep(8)  # stay alive
                ws.close()
            except Exception as e:
                errors.append(f"a: {e}")

        def client_b():
            try:
                ws = connect(self.url)
                ws.send(code)
                time.sleep(8)  # stay alive
                ws.close()
            except Exception as e:
                errors.append(f"b: {e}")

        t1 = threading.Thread(target=client_a)
        t2 = threading.Thread(target=client_b)
        t1.start(); t2.start()

        time.sleep(2)  # let A+B pair first

        # Third client tries to join the ACTIVE room
        def third_client():
            try:
                ws3 = connect(self.url, timeout=5)
                ws3.send(code)
                time.sleep(1)
                # Try to send data — if paired, it would be forwarded
                ws3.send_binary(b"intruder data")
                try:
                    data = ws3.recv()
                    # Empty string = server closed connection (4001 room full)
                    if data == "" or data == b"" or not data:
                        third_result[0] = "rejected"
                    else:
                        third_result[0] = f"paired:{data!r}"
                except Exception:
                    third_result[0] = "rejected"
                ws3.close()
            except websocket.WebSocketConnectionClosedException:
                third_result[0] = "rejected"
            except Exception as e:
                if "4001" in str(e) or "Connection" in str(e) or "closed" in str(e).lower():
                    third_result[0] = "rejected"
                else:
                    third_result[0] = f"error: {e}"

        t3 = threading.Thread(target=third_client)
        t3.start()
        t3.join(10)
        t1.join(TIMEOUT); t2.join(TIMEOUT)

        if third_result[0] == "rejected":
            return TestResult("room_full", True, details="Third client rejected by server")
        if third_result[0] and third_result[0].startswith("paired:"):
            return TestResult("room_full", False,
                              error=f"Third client was PAIRED — room-full not enforced! Data: {third_result[0]}")
        return TestResult("room_full", False, error=f"Unexpected: {third_result[0]}")

    def test_no_session_code(self) -> TestResult:
        """Client that doesn't send session code should be disconnected by server."""
        try:
            ws = connect(self.url, timeout=20)
            # Don't send session code — just wait
            t0 = time.time()
            try:
                data = ws.recv()
                elapsed = time.time() - t0
                # Server should close the connection (recv returns empty or throws)
                if data == "" or data == b"":
                    return TestResult("no_session_code", True,
                                      details=f"Server closed connection after {elapsed:.0f}s")
                # Server sent actual data to a client with no session — BAD
                return TestResult("no_session_code", False,
                                  error=f"Server sent data to unauthenticated client: {data!r}")
            except websocket.WebSocketConnectionClosedException:
                elapsed = time.time() - t0
                return TestResult("no_session_code", True,
                                  details=f"Server closed connection after {elapsed:.0f}s")
            except websocket.WebSocketTimeoutException:
                return TestResult("no_session_code", False,
                                  error="Server kept connection open for 20s+ without session code")
        except Exception as e:
            return TestResult("no_session_code", False, error=f"Unexpected: {e}")

    # ── 3. Reliability Tests ─────────────────────────────────────────

    def test_sudden_disconnect(self) -> TestResult:
        """Sender disconnects abruptly — receiver must get data AND then detect disconnect."""
        code = random_code()
        got_data = [False]
        got_disconnect = [False]
        errors = []

        def sender():
            try:
                ws = connect(self.url)
                ws.send(code)
                time.sleep(2)
                ws.send_binary(b"before crash")
                time.sleep(0.5)
                # Abrupt close — kill the socket without close handshake
                ws.sock.close()
            except Exception as e:
                errors.append(f"sender: {e}")

        def receiver():
            try:
                ws = connect(self.url, timeout=15)
                ws.send(code)
                # Step 1: MUST receive the data that was sent before crash
                data = ws.recv()
                if data == b"before crash":
                    got_data[0] = True
                # Step 2: MUST detect that peer disconnected
                try:
                    ws.recv()  # should error or return empty
                except Exception:
                    got_disconnect[0] = True
                try:
                    ws.close()
                except Exception:
                    pass
            except Exception as e:
                errors.append(f"receiver: {e}")

        t1 = threading.Thread(target=sender)
        t2 = threading.Thread(target=receiver)
        t1.start(); t2.start()
        t1.join(TIMEOUT); t2.join(TIMEOUT)

        if errors:
            return TestResult("sudden_disconnect", False, error="; ".join(errors))
        if got_data[0] and got_disconnect[0]:
            return TestResult("sudden_disconnect", True, details="Data received + disconnect detected")
        if got_data[0] and not got_disconnect[0]:
            return TestResult("sudden_disconnect", False, error="Got data but didn't detect disconnect")
        if not got_data[0] and got_disconnect[0]:
            return TestResult("sudden_disconnect", False, error="Detected disconnect but data was lost")
        return TestResult("sudden_disconnect", False, error="Neither data nor disconnect detected")

    def test_reconnect_same_code(self) -> TestResult:
        """After full session, same code can be reused."""
        code = random_code()
        msg1 = b"Session 1 data"
        msg2 = b"Session 2 data"

        for attempt, msg in enumerate([msg1, msg2], 1):
            data, errors = _run_pair(self.url, code, msg, send_delay=2)
            if errors:
                return TestResult("reconnect_same_code", False, error=f"Attempt {attempt}: {'; '.join(errors)}")
            if data != msg:
                return TestResult("reconnect_same_code", False, error=f"Attempt {attempt}: got {data!r}")
            time.sleep(2)  # wait for full cleanup

        return TestResult("reconnect_same_code", True, details="2 sessions with same code OK")

    # ── 4. Performance Tests ─────────────────────────────────────────

    def test_throughput(self) -> TestResult:
        """Measure relay throughput with continuous data stream."""
        code = random_code()
        chunk_size = 512 * 1024  # 512 KB
        n_chunks = 20  # 10 MB total
        total_received = [0]
        t_start = [0.0]
        t_end = [0.0]
        errors = []

        def sender():
            try:
                ws = connect(self.url)
                ws.send(code)
                time.sleep(2)
                chunk = random_bytes(chunk_size)
                t_start[0] = time.time()
                for i in range(n_chunks):
                    ws.send_binary(chunk)
                ws.send_binary(b"DONE")
                time.sleep(1)
                ws.close()
            except Exception as e:
                errors.append(f"sender: {e}")

        def receiver():
            try:
                ws = connect(self.url)
                ws.send(code)
                while True:
                    data = ws.recv()
                    if isinstance(data, bytes):
                        if data == b"DONE":
                            t_end[0] = time.time()
                            break
                        total_received[0] += len(data)
                    elif isinstance(data, str) and data == "DONE":
                        t_end[0] = time.time()
                        break
                ws.close()
            except Exception as e:
                errors.append(f"receiver: {e}")

        t1 = threading.Thread(target=sender)
        t2 = threading.Thread(target=receiver)
        t1.start(); t2.start()
        t1.join(60); t2.join(60)

        if errors:
            return TestResult("throughput", False, error="; ".join(errors))
        expected_bytes = chunk_size * n_chunks  # 10 MB
        if t_end[0] > t_start[0] and total_received[0] >= expected_bytes * 0.95:
            duration = t_end[0] - t_start[0]
            mb = total_received[0] / (1024 * 1024)
            speed = mb / duration
            return TestResult("throughput", True, details=f"{mb:.1f} MB in {duration:.1f}s = {speed:.1f} MB/s")
        return TestResult("throughput", False,
                          error=f"Received {total_received[0]} bytes, expected >= {int(expected_bytes * 0.95)}")

    def test_latency(self) -> TestResult:
        """Measure round-trip latency (ping-pong)."""
        code = random_code()
        latencies = []
        errors = []

        def pinger():
            try:
                ws = connect(self.url)
                ws.send(code)
                time.sleep(2)
                for i in range(20):
                    t0 = time.time()
                    ws.send_binary(f"ping-{i}".encode())
                    resp = ws.recv()
                    lat = (time.time() - t0) * 1000
                    latencies.append(lat)
                ws.send_binary(b"QUIT")
                ws.close()
            except Exception as e:
                errors.append(f"pinger: {e}")

        def ponger():
            try:
                ws = connect(self.url)
                ws.send(code)
                while True:
                    data = ws.recv()
                    if isinstance(data, bytes) and data == b"QUIT":
                        break
                    if isinstance(data, str) and data == "QUIT":
                        break
                    ws.send_binary(data if isinstance(data, bytes) else data.encode())
                ws.close()
            except Exception as e:
                errors.append(f"ponger: {e}")

        t1 = threading.Thread(target=pinger)
        t2 = threading.Thread(target=ponger)
        t1.start(); t2.start()
        t1.join(TIMEOUT); t2.join(TIMEOUT)

        if errors:
            return TestResult("latency", False, error="; ".join(errors))
        if latencies:
            avg = sum(latencies) / len(latencies)
            mn = min(latencies)
            mx = max(latencies)
            return TestResult("latency", True, details=f"avg={avg:.0f}ms min={mn:.0f}ms max={mx:.0f}ms ({len(latencies)} pings)")
        return TestResult("latency", False, error="No latency data collected")

    def test_concurrent_rooms(self) -> TestResult:
        """5 pairs simultaneously — all should work."""
        n_rooms = 5
        results = [None] * n_rooms

        def pair(idx):
            code = random_code()
            msg = os.urandom(1024)  # 1 KB
            data, errors = _run_pair(self.url, code, msg, send_delay=3)
            results[idx] = (data == msg and not errors)

        threads = [threading.Thread(target=pair, args=(i,)) for i in range(n_rooms)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(TIMEOUT * 2)

        passed = sum(1 for r in results if r)
        if passed == n_rooms:
            return TestResult("concurrent_rooms", True, details=f"{n_rooms}/{n_rooms} OK")
        return TestResult("concurrent_rooms", False, error=f"Only {passed}/{n_rooms} succeeded")


# ── CLI ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SecureShare Relay Server Test Suite")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"Relay server URL (default: {DEFAULT_URL})")
    parser.add_argument("--only", help="Run only tests matching this string")
    parser.add_argument("--list", action="store_true", help="List all tests")
    args = parser.parse_args()

    if args.list:
        tests = [
            "1.1_basic_relay", "1.2_bidirectional", "1.3_binary_1mb",
            "1.4_multiple_rooms", "1.5_session_isolation", "1.6_delayed_peer",
            "1.7_disconnect_cleanup", "2.1_tls", "2.2_room_full",
            "2.3_no_session_code", "3.1_sudden_disconnect",
            "3.2_reconnect_same_code", "4.1_throughput", "4.2_latency",
            "4.3_concurrent_rooms",
        ]
        print("Available tests:")
        for t in tests:
            print(f"  {t}")
        return

    # DNS warmup — DuckDNS can be slow on CI runners
    hostname = urlparse(args.url).hostname
    if hostname:
        print(f"  DNS warmup: {hostname} ...", end=" ", flush=True)
        try:
            _resolve_host(hostname, retries=5)
            print("OK")
        except socket.gaierror as e:
            print(f"FAILED: {e}")
            print("  (DNS not resolving — tests will likely fail)")

    tester = RelayTester(args.url)
    results = tester.run_all(only=args.only)
    sys.exit(0 if all(r.passed for r in results) else 1)


if __name__ == "__main__":
    main()
