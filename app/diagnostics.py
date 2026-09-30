"""
SecureShare — connectivity diagnostics (no GUI).

Five sequential checks against the relay: internet, DNS, TLS, WebSocket,
latency. Results are reported through callbacks so the same logic can be
driven by the diagnostics window or by tests.
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.request
from typing import Callable, Optional
from urllib.parse import urlparse

from .config import VPS_RELAY_URL
from .i18n import t

CHECKS = ("internet", "dns", "tls", "websocket", "latency")

# report_row(check_key, ok, detail_text, color_override)
RowCB = Callable[[str, bool, str, Optional[str]], None]
# report_summary(text, color)
SummaryCB = Callable[[str, str], None]

SKIPPED_COLOR = "#888888"
OK_COLOR, WARN_COLOR, BAD_COLOR = "#2ecc71", "#f39c12", "#e74c3c"


def run_checks(report_row: RowCB, report_summary: SummaryCB) -> int:
    """Run all checks; returns how many passed."""
    parsed = urlparse(VPS_RELAY_URL)
    host = parsed.hostname or "secureshare-relay.duckdns.org"
    port = parsed.port or 443
    total = len(CHECKS)

    def skip_rest(after: str, reason_key: str) -> None:
        for key in CHECKS[CHECKS.index(after) + 1:]:
            report_row(key, False, t(reason_key), SKIPPED_COLOR)

    # 1. Internet connectivity (TCP 443 is rarely blocked, unlike outbound port 53)
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=5).close()
        report_row("internet", True, t("diag_connected"), None)
    except Exception:
        report_row("internet", False, t("diag_no_connection"), None)
        skip_rest("internet", "diag_skipped_no_internet")
        report_summary(t("diag_result", passed=0, total=total), BAD_COLOR)
        return 0
    passed = 1

    # 2. DNS resolution
    try:
        t0 = time.perf_counter()
        ip = socket.gethostbyname(host)
        report_row("dns", True, f"{ip} ({(time.perf_counter() - t0) * 1000:.0f} ms)", None)
        passed += 1
    except Exception:
        report_row("dns", False, t("diag_dns_fail", host=host), None)
        skip_rest("dns", "diag_skipped_dns_error")
        report_summary(t("diag_result", passed=passed, total=total), BAD_COLOR)
        return passed

    # 3. TLS certificate
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "Unknown")
                report_row("tls", True, f"{issuer} ({cert.get('notAfter', '?')})", None)
                passed += 1
    except ssl.SSLCertVerificationError:
        report_row("tls", False, t("diag_tls_invalid"), None)
    except Exception as exc:
        report_row("tls", False, t("diag_tls_error", error=type(exc).__name__), None)

    # 4. WebSocket (websocket-client is what transfers use and what the .exe bundles)
    try:
        import websocket
        t0 = time.perf_counter()
        ws = websocket.create_connection(VPS_RELAY_URL, timeout=5)
        ms = (time.perf_counter() - t0) * 1000
        ws.close()
        report_row("websocket", True, f"OK ({ms:.0f} ms)", None)
        passed += 1
    except Exception:
        # Fallback: plain HTTPS health check
        try:
            health_url = VPS_RELAY_URL.replace("wss://", "https://") + "/health"
            t0 = time.perf_counter()
            resp = urllib.request.urlopen(health_url, timeout=5)
            ms = (time.perf_counter() - t0) * 1000
            if resp.status == 200:
                report_row("websocket", True, f"OK (HTTP, {ms:.0f} ms)", None)
                passed += 1
            else:
                report_row("websocket", False, f"HTTP {resp.status}", None)
        except Exception:
            report_row("websocket", False, t("diag_ws_fail"), None)

    # 5. Latency (3 TCP connects, median)
    try:
        pings = []
        for _ in range(3):
            t0 = time.perf_counter()
            socket.create_connection((host, port), timeout=5).close()
            pings.append((time.perf_counter() - t0) * 1000)
            time.sleep(0.1)
        median = sorted(pings)[1]
        if median < 100:
            quality, color = t("diag_quality_excellent"), OK_COLOR
        elif median < 250:
            quality, color = t("diag_quality_good"), "#f1c40f"
        else:
            quality, color = t("diag_quality_slow"), "#e67e22"
        report_row("latency", True, f"{median:.0f} ms ({quality})", color)
        passed += 1
    except Exception:
        report_row("latency", False, t("diag_latency_fail"), None)

    if passed == total:
        report_summary(t("diag_all_ok", passed=passed, total=total), OK_COLOR)
    elif passed >= 3:
        report_summary(t("diag_partial", passed=passed, total=total), WARN_COLOR)
    else:
        report_summary(t("diag_problems", passed=passed, total=total), BAD_COLOR)
    return passed
