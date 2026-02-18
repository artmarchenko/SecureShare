"""
SecureShare — configuration constants.
"""

import ssl

# ── MQTT ──────────────────────────────────────────────────────────────
# List of free public brokers to try in order (first available wins).
# All support TLS on port 8883.
MQTT_BROKERS = [
    "broker.emqx.io",        # EMQX public broker — most reliable
    "mqtt.eclipseprojects.io",# Eclipse public broker
    "test.mosquitto.org",     # Mosquitto test broker
]
MQTT_BROKER = MQTT_BROKERS[0]       # default (may be overridden at runtime)
MQTT_PORT = 8883                    # TLS port
MQTT_TOPIC_PREFIX = "secureshare/v2"
MQTT_KEEPALIVE = 60

# ── STUN servers (for public IP discovery) ─────────────────────────
STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
    ("stun.ekiga.net", 3478),
]

# ── Transfer ───────────────────────────────────────────────────────
TCP_CHUNK_SIZE = 1024 * 1024        # 1 MB per TCP chunk
UDP_PAYLOAD_SIZE = 32 * 1024        # 32 KB per UDP datagram payload
UDP_WINDOW_SIZE = 64                # sliding window
UDP_ACK_INTERVAL = 0.05            # 50 ms between ACKs
UDP_RETRANSMIT_TIMEOUT = 1.0       # seconds before retransmit
UDP_MAX_RETRIES = 20

# ── WebSocket Relay (Cloudflare Tunnel) ───────────────────────────
#
# Used when direct P2P fails.  Sender runs a local WebSocket relay
# server; Cloudflare Tunnel exposes it publicly.  No message size
# limits, no broker queues — just a raw byte pipe.
#
WS_RELAY_CHUNK_SIZE = 512 * 1024   # 512 KB — fewer CF frames = less per-frame overhead
WS_TUNNEL_COUNT     = 2            # parallel CF tunnels to multiply bandwidth

# ── MQTT Relay (last-resort fallback if CF tunnel unavailable) ─────
#
# Public broker limits (HiveMQ free tier):
#   Max message size  : ~256 KB  → chunk must be WELL below this
#   Session queue     : ~1000 messages before broker drops
#
# Strategy:
#   64 KB chunks  → safely under broker message-size limit (no silent drops)
#   QoS 1 data    → broker guarantees delivery (no app-level retransmit needed)
#   16 inflight   → 16 × 64 KB = 1 MB in flight; won't overflow broker queue
#   QoS 1 ctl     → meta / done / ack must also be reliable
#
MQTT_RELAY_CHUNK_SIZE  = 64 * 1024   # 64 KB — safely within broker limits
MQTT_RELAY_QOS         = 1           # at-least-once for control messages
MQTT_RELAY_DATA_QOS    = 1           # QoS 1 for data: broker must deliver
MQTT_RELAY_INFLIGHT    = 16          # max concurrent unacked messages
MQTT_RELAY_BATCH_SIZE  = 32          # unused, kept for compatibility
MQTT_RELAY_RATE_LIMIT  = 12          # unused, kept for compatibility

# ── Networking ─────────────────────────────────────────────────────
CONNECTION_TIMEOUT = 30             # seconds
HOLE_PUNCH_TIMEOUT = 15            # seconds
HOLE_PUNCH_INTERVAL = 0.3         # seconds between punch packets
UPNP_TIMEOUT = 3                   # seconds
DEFAULT_PORT = 0                    # 0 = random

# ── Session ────────────────────────────────────────────────────────
SESSION_CODE_LENGTH = 8             # characters in session code

# ── App ────────────────────────────────────────────────────────────
APP_NAME = "SecureShare"
APP_VERSION = "2.0.0"


# ── MQTT TLS helper ───────────────────────────────────────────────

def mqtt_setup_tls(client) -> None:
    """Configure TLS on a paho-mqtt Client for secure broker connection."""
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        ctx = ssl.create_default_context()
    client.tls_set_context(ctx)
