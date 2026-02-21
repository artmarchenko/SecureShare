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

# ── Resume ─────────────────────────────────────────────────────────
RESUME_MANIFEST_EXT  = ".resume"          # manifest file extension
RESUME_MAX_AGE       = 7 * 24 * 3600      # 7 days — auto-cleanup
RESUME_SAVE_INTERVAL = 64                 # save manifest every N chunks

# ── Auto-reconnect ────────────────────────────────────────────────
RECONNECT_MAX_RETRIES = 5                 # max reconnect attempts
RECONNECT_BASE_DELAY  = 5                 # seconds (exponential backoff)
RECONNECT_MAX_DELAY   = 60                # seconds cap

# ── App ────────────────────────────────────────────────────────────
APP_NAME = "SecureShare"
APP_VERSION = "3.3.0"

# ── Links ──────────────────────────────────────────────────────────
HOMEPAGE_URL = "https://secureshare-relay.duckdns.org"
DONATE_URL = "https://ko-fi.com/secureshare"
GITHUB_URL = "https://github.com/artmarchenko/SecureShare"
