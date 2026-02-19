"""
SecureShare — configuration constants.

v3: VPS-only architecture. All legacy P2P / MQTT / Cloudflare
constants have been removed.
"""

# ── VPS Relay Server ──────────────────────────────────────────────
VPS_RELAY_URL = "wss://secureshare-relay.duckdns.org"
VPS_MAX_FILE_SIZE = 5 * 1024**3        # 5 GiB — server session limit
VPS_CHUNK_SIZE = 512 * 1024            # 512 KB per WebSocket chunk

# ── Protocol Version ──────────────────────────────────────────────
PROTOCOL_VERSION     = 1   # current wire-protocol version
MIN_PROTOCOL_VERSION = 1   # minimum compatible version (reject older)

# ── Session ────────────────────────────────────────────────────────
SESSION_CODE_LENGTH = 8

# ── App ────────────────────────────────────────────────────────────
APP_NAME = "SecureShare"
APP_VERSION = "3.0.4"
