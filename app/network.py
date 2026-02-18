"""
SecureShare — networking helpers.

STUN client (public IP discovery), UPnP port mapping, UDP hole punching.
"""

from __future__ import annotations

import os
import socket
import struct
import logging
import time
import threading
from typing import Optional

from .config import (
    STUN_SERVERS,
    UPNP_TIMEOUT,
    HOLE_PUNCH_TIMEOUT,
    HOLE_PUNCH_INTERVAL,
)

log = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════════════
#  Local network helpers
# ════════════════════════════════════════════════════════════════════

def _is_virtual_ip(ip: str) -> bool:
    """Heuristic: detect IPs from virtual adapters (VirtualBox, VMware, Docker, etc.)."""
    prefixes = (
        "192.168.56.",   # VirtualBox host-only
        "192.168.137.",  # Windows ICS / Mobile Hotspot
        "172.17.",       # Docker default bridge
        "172.18.",       # Docker
        "10.0.75.",      # Docker for Windows (legacy)
        "100.64.",       # CGNAT / Tailscale
    )
    return ip.startswith(prefixes)


def get_local_ips() -> list[str]:
    """Return list of non-loopback local IPv4 addresses.
    The default-route IP is always first; virtual-adapter IPs are last."""
    all_ips: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in all_ips:
                all_ips.append(ip)
    except Exception:
        pass

    # Discover default route IP (the one that routes to the internet)
    default_ip: Optional[str] = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        default_ip = s.getsockname()[0]
        s.close()
        if default_ip not in all_ips:
            all_ips.append(default_ip)
    except Exception:
        pass

    # Sort: default IP first → real IPs → virtual IPs last
    def _sort_key(ip: str) -> tuple[int, str]:
        if ip == default_ip:
            return (0, ip)
        if _is_virtual_ip(ip):
            return (2, ip)
        return (1, ip)

    all_ips.sort(key=_sort_key)
    return all_ips


# ════════════════════════════════════════════════════════════════════
#  STUN client  (RFC 5389 – Binding Request, minimal implementation)
# ════════════════════════════════════════════════════════════════════

_STUN_MAGIC = 0x2112A442
_STUN_BIND_REQ = 0x0001
_STUN_BIND_RESP = 0x0101
_ATTR_MAPPED_ADDR = 0x0001
_ATTR_XOR_MAPPED_ADDR = 0x0020


def stun_request(
    local_port: int = 0,
    existing_sock: socket.socket | None = None,
) -> tuple[Optional[str], Optional[int], Optional[socket.socket]]:
    """
    Send STUN Binding Request and return (public_ip, public_port, sock).
    If *existing_sock* is given, it will be reused (to preserve port mapping).
    Returns (None, None, None) on failure.
    """
    sock = existing_sock
    if sock is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", local_port))
    sock.settimeout(3)

    txn_id = os.urandom(12)
    header = struct.pack("!HHI", _STUN_BIND_REQ, 0, _STUN_MAGIC) + txn_id

    for host, port in STUN_SERVERS:
        try:
            addr = socket.getaddrinfo(host, port, socket.AF_INET)[0][4]
            sock.sendto(header, addr)
            data, _ = sock.recvfrom(2048)

            msg_type, msg_len = struct.unpack_from("!HH", data, 0)
            magic = struct.unpack_from("!I", data, 4)[0]

            if msg_type != _STUN_BIND_RESP or magic != _STUN_MAGIC:
                continue

            # Check transaction ID matches
            if data[8:20] != txn_id:
                continue

            # Parse attributes
            offset = 20
            while offset < 20 + msg_len:
                attr_type, attr_len = struct.unpack_from("!HH", data, offset)
                attr_start = offset + 4

                if attr_type == _ATTR_XOR_MAPPED_ADDR:
                    family = data[attr_start + 1]
                    if family == 0x01:  # IPv4
                        xport = struct.unpack_from("!H", data, attr_start + 2)[0]
                        xip = struct.unpack_from("!I", data, attr_start + 4)[0]
                        pub_port = xport ^ (_STUN_MAGIC >> 16)
                        pub_ip_int = xip ^ _STUN_MAGIC
                        pub_ip = socket.inet_ntoa(struct.pack("!I", pub_ip_int))
                        log.info("STUN: public address %s:%d", pub_ip, pub_port)
                        return pub_ip, pub_port, sock

                elif attr_type == _ATTR_MAPPED_ADDR:
                    family = data[attr_start + 1]
                    if family == 0x01:
                        pub_port = struct.unpack_from("!H", data, attr_start + 2)[0]
                        pub_ip = socket.inet_ntoa(data[attr_start + 4 : attr_start + 8])
                        log.info("STUN: public address %s:%d", pub_ip, pub_port)
                        return pub_ip, pub_port, sock

                # Advance to next attribute (4-byte aligned)
                offset = attr_start + attr_len
                if attr_len % 4:
                    offset += 4 - (attr_len % 4)

        except (socket.timeout, OSError) as exc:
            log.debug("STUN server %s:%d failed: %s", host, port, exc)
            continue

    if existing_sock is None:
        sock.close()
    return None, None, None


# ════════════════════════════════════════════════════════════════════
#  UPnP IGD port mapping (via miniupnpc)
# ════════════════════════════════════════════════════════════════════

_upnp = None  # singleton UPnP handle


def _get_upnp():
    global _upnp
    if _upnp is not None:
        return _upnp
    try:
        import miniupnpc  # type: ignore

        u = miniupnpc.UPnP()
        u.discoverdelay = UPNP_TIMEOUT * 1000
        n = u.discover()
        if n > 0:
            u.selectigd()
            _upnp = u
            log.info("UPnP: found IGD — %s", u.externalipaddress())
            return u
    except Exception as exc:
        log.debug("UPnP unavailable: %s", exc)
    return None


def upnp_get_external_ip() -> Optional[str]:
    u = _get_upnp()
    if u:
        try:
            return u.externalipaddress()
        except Exception:
            pass
    return None


def upnp_add_mapping(
    internal_port: int,
    external_port: int,
    protocol: str = "TCP",
    description: str = "SecureShare",
    duration: int = 3600,
) -> bool:
    """Add a port mapping via UPnP.  Returns True on success."""
    u = _get_upnp()
    if not u:
        return False
    try:
        local_ip = get_local_ips()[0]
        u.addportmapping(
            external_port,
            protocol,
            local_ip,
            internal_port,
            description,
            "",
            duration,
        )
        log.info(
            "UPnP: mapped external %s:%d → %s:%d",
            protocol,
            external_port,
            local_ip,
            internal_port,
        )
        return True
    except Exception as exc:
        log.debug("UPnP addportmapping failed: %s", exc)
        return False


def upnp_remove_mapping(external_port: int, protocol: str = "TCP") -> bool:
    u = _get_upnp()
    if not u:
        return False
    try:
        u.deleteportmapping(external_port, protocol)
        return True
    except Exception:
        return False


# ════════════════════════════════════════════════════════════════════
#  UDP hole punching
# ════════════════════════════════════════════════════════════════════

_PUNCH_MAGIC = b"SECURESHARE_PUNCH"
_PUNCH_ACK = b"SECURESHARE_PUNCHED"


def udp_hole_punch(
    sock: socket.socket,
    peer_ip: str,
    peer_port: int,
    timeout: float = HOLE_PUNCH_TIMEOUT,
    on_status: callable = None,
) -> bool:
    """
    Attempt to punch a UDP hole to *peer_ip:peer_port*.
    Both sides must call this simultaneously.
    Returns True if the hole was punched.
    """
    sock.settimeout(HOLE_PUNCH_INTERVAL)
    peer_addr = (peer_ip, peer_port)
    deadline = time.monotonic() + timeout
    punched = False

    if on_status:
        on_status(f"UDP hole punch → {peer_ip}:{peer_port} ...")

    while time.monotonic() < deadline:
        try:
            sock.sendto(_PUNCH_MAGIC, peer_addr)
        except OSError:
            pass

        try:
            data, addr = sock.recvfrom(64)
            if addr[0] == peer_ip:
                if data == _PUNCH_MAGIC:
                    # Peer's punch received — send ACK
                    for _ in range(3):
                        sock.sendto(_PUNCH_ACK, peer_addr)
                    punched = True
                    break
                elif data == _PUNCH_ACK:
                    punched = True
                    break
        except socket.timeout:
            continue

    if punched and on_status:
        on_status("UDP hole punch — успішно! ✓")
    elif not punched and on_status:
        on_status("UDP hole punch — не вдалося ✗")

    log.info("UDP hole punch to %s:%d → %s", peer_ip, peer_port, punched)
    return punched


# ════════════════════════════════════════════════════════════════════
#  TCP helpers
# ════════════════════════════════════════════════════════════════════

def tcp_listen(port: int = 0) -> socket.socket:
    """Create a TCP server socket listening on *port* (0 = random)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    srv.settimeout(CONNECTION_TIMEOUT)
    log.info("TCP listening on port %d", srv.getsockname()[1])
    return srv


def tcp_connect(
    host: str,
    port: int,
    timeout: float = 10,
) -> Optional[socket.socket]:
    """Try to open a TCP connection; return socket or None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        log.info("TCP connected to %s:%d", host, port)
        return s
    except (OSError, socket.timeout) as exc:
        log.debug("TCP connect to %s:%d failed: %s", host, port, exc)
        return None


def tcp_connect_any(
    hosts: list[str],
    port: int,
    timeout: float = 8,
    on_status: callable = None,
) -> Optional[socket.socket]:
    """
    Try to TCP-connect to *port* on every host in *hosts* **in parallel**.
    Returns the first successful socket (others are closed), or None.
    """
    if not hosts:
        return None

    result: Optional[socket.socket] = None
    lock = threading.Lock()

    def _try(host: str):
        nonlocal result
        if on_status:
            on_status(f"  Пробую {host}:{port}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            with lock:
                if result is None:
                    result = s
                    log.info("TCP parallel: connected to %s:%d", host, port)
                    if on_status:
                        on_status(f"  TCP з'єднання з {host}:{port} ✓")
                else:
                    s.close()  # another thread already won
        except (OSError, socket.timeout):
            pass

    threads = [threading.Thread(target=_try, args=(h,), daemon=True) for h in hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 2)

    return result


from .config import CONNECTION_TIMEOUT
