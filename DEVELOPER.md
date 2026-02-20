# SecureShare — Developer Guide

> Comprehensive technical documentation for developers, auditors, and contributors.
>
> **Version:** 3.2 · **Architecture:** VPS-only relay · **Author:** Artem Marchenko

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Security Model](#3-security-model)
4. [Wire Protocol](#4-wire-protocol)
5. [Client Application](#5-client-application)
6. [Relay Server](#6-relay-server)
7. [Infrastructure](#7-infrastructure)
8. [CI/CD Pipeline](#8-cicd-pipeline)
9. [Configuration Reference](#9-configuration-reference)
10. [Development Setup](#10-development-setup)
11. [Testing](#11-testing)
12. [Secrets Management](#12-secrets-management)
13. [Known Limitations](#13-known-limitations)
14. [Threat Model](#14-threat-model)

---

## 1. Overview

SecureShare is a desktop application for **one-time secure file transfers** between two users over the internet. No registration, no account, no network configuration required.

### Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Zero-knowledge relay** | Server never sees plaintext; all data is E2E encrypted |
| **Minimal trust** | Users verify connection via visual security code (anti-MITM) |
| **Single binary** | Distributed as a standalone `.exe` — no installation needed |
| **Ephemeral sessions** | Session codes are single-use, rooms auto-expire after 30 min |
| **Defense in depth** | TLS transport + E2E encryption + signaling encryption + integrity check |

### How It Works (User Perspective)

```
Sender                                               Receiver
  1. Select file                                       2. Enter session code
  2. Get session code → share with receiver             3. Click "Receive"
  3. Compare verification code ←→ Compare verification code
  4. Wait for transfer ←→ Wait for transfer
  5. Done ✓                                            5. File saved ✓
```

---

## 2. Architecture

### System Diagram

```
┌─────────────────┐                                     ┌─────────────────┐
│   Sender (GUI)  │                                     │  Receiver (GUI) │
│                 │                                     │                 │
│  CustomTkinter  │                                     │  CustomTkinter  │
│  CryptoSession  │                                     │  CryptoSession  │
│  VPSRelaySender │                                     │ VPSRelayReceiver│
└────────┬────────┘                                     └────────┬────────┘
         │ WSS (TLS 1.2+)                                        │ WSS (TLS 1.2+)
         │                                                       │
         ▼                                                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Caddy Reverse Proxy                              │
│                                                                         │
│  • Auto-TLS via Let's Encrypt                                          │
│  • HSTS, X-Content-Type-Options, X-Frame-Options                       │
│  • X-Forwarded-For injection (real client IP)                          │
│  • /health endpoint (responds 200 OK)                                  │
│  • /download/* endpoint (serves .zip releases)                         │
│  Port 443 (HTTPS/WSS) ─────────────────────────────► Port 8765 (WS)   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Relay Server (Python + websockets)                 │
│                                                                         │
│  • Pairs clients by session code hash                                  │
│  • Pipes raw bytes A ↔ B (zero inspection)                             │
│  • Rate limiting per real IP                                           │
│  • Per-session 5 GB data limit                                         │
│  • Backpressure/flow control                                           │
│  • Room timeout (30 min auto-cleanup)                                  │
│  • Health check on :8766                                               │
│  • Graceful shutdown (SIGTERM/SIGINT)                                  │
│  Port 8765 (WS) + Port 8766 (HTTP health)                             │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| GUI | Python + CustomTkinter | Desktop interface, transfer orchestration |
| Encryption | `cryptography` library | X25519, AES-256-GCM, HKDF-SHA256 |
| Transport (client) | `websocket-client` (sync) | WebSocket connection to relay |
| Transport (server) | `websockets` (async) | High-performance async WebSocket server |
| TLS Termination | Caddy 2 | Auto-provisioned Let's Encrypt certificates |
| Container | Docker + Docker Compose | Isolation, reproducible deploys |
| Hosting | Oracle Cloud (ARM VM) | Always Free tier VM |
| DNS | DuckDNS | Free dynamic DNS subdomain |
| CI/CD | GitHub Actions | Lint → Test → Build → Release → Deploy |

### Project Structure

```
fileshare/
├── app/                          # Client application
│   ├── __init__.py
│   ├── config.py                 # Constants: URLs, limits, version, protocol
│   ├── crypto_utils.py           # X25519, AES-256-GCM, HKDF, signaling crypto
│   ├── gui.py                    # CustomTkinter GUI + transfer orchestration
│   └── ws_relay.py               # VPS WebSocket relay sender/receiver
│
├── server/                       # Relay server (deployed to VPS)
│   ├── relay_server.py           # Async WebSocket relay (Python + websockets)
│   ├── Dockerfile                # Docker image (python:3.11-slim, non-root)
│   ├── docker-compose.yml        # Services: relay + caddy
│   ├── Caddyfile                 # Reverse proxy + auto-TLS + security headers
│   ├── requirements.txt          # Server dependencies (websockets)
│   ├── test_relay.py             # Server test suite (16+ tests)
│   └── DEPLOY.md                 # Manual deployment guide
│
├── assets/                       # Application assets
│   ├── SecureShare.png           # Logo (1024×1024 RGBA)
│   ├── SecureShare.ico           # Multi-size icon (16–256px)
│   └── icon_32.png               # 32×32 icon for window/taskbar
│
├── .github/workflows/            # CI/CD
│   ├── ci.yml                    # Lint + import check (every push)
│   └── release.yml               # Build + test + release + deploy (on v* tag)
│
├── main.py                       # Entry point (logging setup + App launch)
├── build.py                      # PyInstaller build script
├── SecureShare.spec              # PyInstaller spec (icon, datas, hidden imports)
├── version_info.txt              # Windows .exe metadata (version, publisher)
├── requirements.txt              # Client Python dependencies
├── .flake8                       # Linter configuration
├── .gitignore                    # Git ignore rules
└── .env                          # Local secrets (not in repo)
```

---

## 3. Security Model

### 3.1. Encryption Layers

SecureShare implements **three independent encryption layers**:

```
Layer 3:  TLS 1.2+  (transport) ─── Caddy ↔ Client
Layer 2:  Signaling Encryption ──── Pre-shared key from session code
Layer 1:  E2E Encryption ────────── X25519 + AES-256-GCM
```

Even if one layer is compromised, the others provide protection:
- **TLS compromised?** → Signaling and E2E encryption still protect data
- **Signaling key guessed?** → E2E encryption still protects file content
- **Server compromised?** → Server never has E2E keys; sees only ciphertext

### 3.2. Cryptographic Algorithms

| Component | Algorithm | Key Size | Purpose |
|-----------|-----------|----------|---------|
| Key Exchange | X25519 (ECDH) | 256-bit | Asymmetric key agreement |
| Key Derivation | HKDF-SHA256 | 256-bit output | Derive AES key from shared secret |
| Data Encryption | AES-256-GCM | 256-bit | Authenticated encryption |
| Signaling Encryption | AES-256-GCM | 256-bit | Protect key exchange messages |
| Signaling Key | HKDF-SHA256 | 256-bit | Derive from session code |
| Integrity | SHA-256 | 256-bit | File hash verification after transfer |
| Nonce | Counter + Prefix | 96-bit | Prevent nonce reuse |

### 3.3. Key Exchange Flow

```
                   Sender                                  Receiver
                     │                                        │
                     │ 1. Generate X25519 key pair            │ 1. Generate X25519 key pair
                     │                                        │
                     │ 2. Derive signaling key from           │ 2. Derive signaling key from
                     │    session code (HKDF)                 │    session code (HKDF)
                     │                                        │
                     │ 3. Send: signaling_encrypt({           │
                     │      type: "pub_key",                  │
                     │      key: <X25519 pub>,                │
                     │      protocol_version: 1,              │
                     │      app_version: "3.2.0",             │
                     │      reconnect_token: <opt>            │
                     │    }) ─────────────────────────────────►│
                     │                                        │
                     │◄─────────────────────────────────────── │ 3. Send: signaling_encrypt({
                     │                                        │      type: "pub_key",
                     │                                        │      key: <X25519 pub>,
                     │                                        │      ...
                     │                                        │    })
                     │                                        │
                     │ 4. ECDH: private × peer_pub            │ 4. ECDH: private × peer_pub
                     │    → raw shared secret                 │    → raw shared secret
                     │                                        │
                     │ 5. HKDF(secret, salt=session_code,     │ 5. HKDF(secret, salt=session_code,
                     │         info="secureshare-v2-aes")     │         info="secureshare-v2-aes")
                     │    → AES-256 key (identical both)      │    → AES-256 key (identical both)
                     │                                        │
                     │ 6. Nonce prefix assignment:             │ 6. Nonce prefix assignment:
                     │    lower pub key → prefix 0            │    higher pub key → prefix 1
                     │    (prevents nonce collision)           │    (prevents nonce collision)
                     │                                        │
```

### 3.4. Nonce Construction

Each nonce is 12 bytes (96 bits), constructed as:

```
┌──────────────┬──────────────────────────────┐
│ Prefix (4B)  │     Counter (8B, big-endian) │
│   0 or 1     │     incrementing per message │
└──────────────┴──────────────────────────────┘
```

- **Prefix** is determined by comparing raw public keys: the peer with the lexicographically "lower" key gets prefix `0`, the other gets `1`
- This ensures **the same (key, nonce) pair is never used twice**, even though both peers share the same AES key
- Counter is 64-bit, allowing up to 2^64 messages per session (practically unlimited)

### 3.5. Signaling Encryption

Before E2E keys are established, signaling messages (public key exchange, verification) are encrypted using a **pre-shared key** derived from the session code:

```python
signaling_key = HKDF(
    algorithm=SHA256,
    length=32,
    salt=b"secureshare-signaling-salt-v2",
    info=b"secureshare-signaling-key",
).derive(session_code.encode())
```

This prevents an eavesdropper on the relay from seeing public keys, protecting against active MITM attacks where an attacker would substitute their own key.

**Signaling encrypt/decrypt:**
- Random 12-byte nonce (safe for few messages)
- AAD: `b"secureshare-signaling-aad"` (fixed)
- Output: `nonce (12B) || ciphertext + GCM tag (16B)`

### 3.6. MITM Verification

After key exchange, both peers compute a **verification code**:

```python
code = SHA256(shared_key + b"secureshare-verify").hexdigest()[:8]
# Displayed as: "E555-EB8B"
```

Users compare this code verbally or through a separate channel. If codes don't match, a MITM attack is in progress, and the session is aborted.

**Verification protocol:**
1. Both peers display the code to their user
2. User confirms → client sends `signaling_encrypt({"type": "verified"})`
3. User rejects → client sends `signaling_encrypt({"type": "verify_reject"})`
4. Both peers must confirm for transfer to proceed

### 3.7. AAD Binding

All E2E encrypted data uses the **session code as AAD** (Associated Authenticated Data) in AES-GCM:

```python
ciphertext = aes.encrypt(nonce, plaintext, session_code.encode())
```

This binds encrypted data to the specific session, preventing:
- **Cross-session substitution**: ciphertext from session A cannot be replayed in session B
- **Ciphertext manipulation**: any modification is detected by GCM authentication

### 3.8. File Integrity

After all chunks are received, the receiver computes `SHA-256` of the saved file and compares it to the sender's hash. This provides an independent integrity check beyond GCM authentication (which verifies individual chunks).

---

## 4. Wire Protocol

### 4.1. Frame Format

Every WebSocket message has a 1-byte type prefix:

```
┌────────┬──────────────────────────────────────┐
│ Type   │ Payload                               │
│ (1B)   │ (variable length)                     │
└────────┴──────────────────────────────────────┘
```

| Type Byte | Hex | Name | Description |
|-----------|-----|------|-------------|
| `S` | `0x53` | Signaling | Key exchange, verification (signaling-encrypted) |
| `C` | `0x43` | Control | Metadata, ACKs, done signals (E2E encrypted) |
| `D` | `0x44` | Data | File chunks (E2E encrypted + compressed) |

### 4.2. Signaling Frame (`0x53`)

```
┌──────┬──────────────────────────────────────────────┐
│ 0x53 │ signaling_encrypt(JSON payload)               │
│ (1B) │ = nonce(12B) + encrypted(JSON + GCM tag 16B) │
└──────┴──────────────────────────────────────────────┘
```

JSON payload types:
- `{"type": "pub_key", "key": "<base64>", "protocol_version": 1, "app_version": "3.2.0", "reconnect_token": "<base64>"}` *(reconnect_token is optional, present on reconnect)*
- `{"type": "verified"}`
- `{"type": "verify_reject"}`

### 4.3. Control Frame (`0x43`)

```
┌──────┬────────────────────────────────────┐
│ 0x43 │ e2e_encrypt(JSON payload)          │
│ (1B) │ = nonce(12B) + encrypted(JSON+tag) │
└──────┴────────────────────────────────────┘
```

JSON payload types:

| Type | Direction | Fields |
|------|-----------|--------|
| `relay_meta` | Sender → Receiver | `name`, `size`, `sha256`, `chunk_size`, `total_chunks`, `transfer_id` |
| `relay_meta_ack` | Receiver → Sender | `resume` (bool, opt), `received_chunks` (list, opt) |
| `relay_done` | Sender → Receiver | `sha256`, `total_chunks` |
| `relay_done_ack` | Receiver → Sender | `verified` (bool) |
| `relay_retransmit` | Receiver → Sender | `missing` (list of chunk indices) |

### 4.4. Data Frame (`0x44`)

```
┌──────┬────────────┬────────────────────────────────────────┐
│ 0x44 │ seq (4B BE)│ e2e_encrypt(compressed_chunk)          │
│ (1B) │            │ = nonce(12B) + encrypted(data+tag 16B) │
└──────┴────────────┴────────────────────────────────────────┘
```

- **seq**: 4-byte big-endian sequence number (chunk index)
- **Compression**: zlib level 1, with flag byte:
  - `0x01` + compressed data (if compression saved >64 bytes)
  - `0x00` + raw data (otherwise)
- **Chunk size**: 512 KB (configurable via `VPS_CHUNK_SIZE`)

### 4.5. Transfer Sequence Diagram

```
Sender                        VPS Relay                      Receiver
  │                              │                               │
  │── session_code (text) ──────►│                               │
  │                              │◄── session_code (text) ───────│
  │                              │  (paired by SHA-256 hash)     │
  │                              │                               │
  │── [S] pub_key+version ──────►│──────────────────────────────►│
  │◄─────────────────────────────│◄── [S] pub_key+version ──────│
  │  (both derive shared key)    │                               │
  │                              │                               │
  │── [S] verified ─────────────►│──────────────────────────────►│
  │◄─────────────────────────────│◄── [S] verified ─────────────│
  │                              │                               │
  │── [C] relay_meta ───────────►│──────────────────────────────►│
  │◄─────────────────────────────│◄── [C] relay_meta_ack ───────│
  │                              │                               │
  │── [D] chunk 0 ──────────────►│──────────────────────────────►│
  │── [D] chunk 1 ──────────────►│──────────────────────────────►│
  │── [D] chunk 2 ──────────────►│──────────────────────────────►│
  │   ...                        │                               │
  │── [D] chunk N ──────────────►│──────────────────────────────►│
  │                              │                               │
  │── [C] relay_done ───────────►│──────────────────────────────►│
  │                              │                               │ (SHA-256 verify)
  │◄─────────────────────────────│◄── [C] relay_done_ack ───────│
  │                              │                               │
  │  (connection closes)         │  (room cleaned up)            │
```

### 4.6. Version Negotiation

During key exchange, both peers include `protocol_version` and `app_version` in the signaling message. Compatibility check:

```
If peer.protocol_version < our MIN_PROTOCOL_VERSION:
    → Reject with error message ("update your app")
If peer.protocol_version > our PROTOCOL_VERSION:
    → Warning ("peer has newer version, consider updating")
```

This ensures forward compatibility: newer clients can connect to older ones as long as protocol changes are backward-compatible.

### 4.7. Retransmission

After receiving `relay_done`, the receiver checks for missing chunks:

1. If chunks are missing → send `relay_retransmit` with list of missing sequence numbers
2. Sender retransmits the requested chunks
3. Sender re-sends `relay_done`
4. Repeat up to 5 rounds

This handles packet loss or processing failures without requiring the full file to be re-sent.

### 4.8. Resume Protocol (v3.1)

If a transfer is interrupted (network loss, user cancel), the receiver saves a `.resume` manifest file alongside the `.part` temporary file. The manifest contains:

```json
{
  "transfer_id": "<sha256(name|size|hash)[:32]>",
  "file_name": "example.zip",
  "file_size": 104857600,
  "file_sha256": "abc...",
  "chunk_size": 524288,
  "total_chunks": 200,
  "received_chunks": [0, 1, 2, 3, ...],
  "timestamp": 1708000000.0
}
```

On the next transfer of the **same file** (any session code):
1. Sender includes `transfer_id` in `relay_meta`
2. Receiver matches `transfer_id` against existing `.resume` manifest
3. If matched → sends `relay_meta_ack` with `resume: true` and `received_chunks` list
4. Sender skips already-received chunks
5. Manifests auto-expire after 7 days (`RESUME_MAX_AGE`)

### 4.9. Auto-Reconnect Protocol (v3.2)

On connection loss **during an active transfer**, both sender and receiver automatically attempt to reconnect (up to `RECONNECT_MAX_RETRIES` attempts with exponential backoff).

**Reconnect token** (identity proof across reconnects):
```
reconnect_token = HMAC-SHA256(shared_key, session_code + "secureshare-reconnect-v1")[:16]
```

After successful verification, both sides compute and store this token. On reconnect:

1. Both peers independently detect the disconnect
2. Wait with exponential backoff: 5s → 10s → 20s → 40s → 60s
3. Reconnect to relay with the **same session code**
4. New X25519 key exchange (includes `reconnect_token` in signaling message)
5. If peer's `reconnect_token` matches our stored token → **auto-verify** (skip popup)
6. If tokens don't match → full verification with user interaction
7. Sender re-sends `relay_meta` → receiver responds with resume info → transfer continues

**Security model:**
- The reconnect token proves the peer participated in the original key exchange
- An attacker would need the previous shared key to forge the token
- The token is encrypted with the signaling key (derived from session code)
- If the token doesn't match, full verification is required (safe fallback)

---

## 5. Client Application

### 5.1. Module Responsibilities

| Module | Lines | Responsibility |
|--------|-------|---------------|
| `config.py` | ~30 | Constants: relay URL, chunk size, version, limits, reconnect/resume |
| `crypto_utils.py` | ~191 | All cryptography: X25519, AES-GCM, HKDF, signaling |
| `ws_relay.py` | ~1280 | `VPSRelaySender` and `VPSRelayReceiver` with auto-reconnect + resume |
| `gui.py` | ~1200 | CustomTkinter GUI, threading, transfer orchestration |
| `main.py` | ~49 | Entry point, logging setup |

### 5.2. Threading Model

```
┌──────────────────────────────────────────────────────┐
│                    Main Thread                        │
│                                                      │
│  CustomTkinter event loop (GUI)                      │
│  • Button handlers start worker threads              │
│  • Progress/status updates via self.after()          │
│  • Verification dialog (modal)                       │
└──────────────────────┬───────────────────────────────┘
                       │ starts
                       ▼
┌──────────────────────────────────────────────────────┐
│                   Worker Thread                       │
│                                                      │
│  VPSRelaySender.send() or VPSRelayReceiver.receive() │
│  • Blocking WebSocket I/O                            │
│  • Auto-reconnect loop (up to 5 retries)             │
│  • Calls on_progress / on_status callbacks           │
│  • Callbacks use self.after() to update GUI safely   │
└──────────────────────┬───────────────────────────────┘
                       │ starts (sender only)
                       ▼
┌──────────────────────────────────────────────────────┐
│               Recv Worker (Sender side)               │
│                                                      │
│  Background thread reading control frames            │
│  • relay_meta_ack, relay_done_ack, relay_retransmit  │
│  • Puts messages into queue.Queue                    │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│             Async Disk Writer (Receiver side)         │
│                                                      │
│  Background thread writing chunks to disk            │
│  • Receives (seq, data) from queue.Queue             │
│  • Seeks to correct offset, writes, flushes          │
│  • Decouples network I/O from disk I/O               │
└──────────────────────────────────────────────────────┘
```

### 5.3. GUI Features

| Feature | Description |
|---------|-------------|
| Session code generation | 8-char random alphanumeric code (format: `xxxx-xxxx`) |
| Copy code button | One-click copy session code to clipboard |
| Paste code button | Paste session code from clipboard into receiver input |
| File size display | Shows human-readable file size after selection |
| 5 GB limit warning | Yellow warning when file exceeds 5 GB session limit |
| Connection status indicator | Color-coded status: Idle (gray), Connecting (yellow), Transferring (green), Error (red) |
| Progress bar | Real-time progress with percentage, bytes transferred, and speed |
| Timestamped log | All events logged with `[HH:MM:SS]` timestamps |
| Log copy/export | Buttons to copy log to clipboard or save to file |
| Help dialog | Step-by-step instructions with colored sections |
| Diagnostics | 5-point connectivity check: Internet, DNS, TLS, WebSocket, Latency |
| Cancel | Stops transfer at any point, closes connection |

### 5.4. Diagnostics Checks

The built-in diagnostics button runs these checks sequentially:

1. **Internet** — TCP connection to `1.1.1.1:443`
2. **DNS** — Resolve relay domain to IP
3. **TLS/SSL** — TLS handshake with relay domain
4. **WebSocket** — Full WSS connection to relay
5. **Latency** — Round-trip time to relay server

---

## 6. Relay Server

### 6.1. Design

The relay server is intentionally minimal:
- **Zero knowledge**: never inspects, logs, or stores payload content
- **Stateless**: all state is in-memory, no database or disk persistence
- **Session codes are hashed**: server stores `SHA-256(code)[:32]` — original code never in memory

### 6.2. Connection Lifecycle

```
Client connects (WSS)
  │
  ├─ Rate limit check (per IP) ── fail → close(4029)
  │
  ├─ Receive session code (15s timeout) ── timeout → close
  │
  ├─ Hash session code → room_id
  │
  ├─ Join room
  │   ├─ Room doesn't exist → create room, wait for peer (5 min)
  │   ├─ Room has 1 peer → join, signal pairing via asyncio.Event
  │   └─ Room has 2 peers → close(4001, "room full")
  │
  ├─ Relay loop
  │   ├─ Read message from client A
  │   ├─ Send to client B (with backpressure)
  │   ├─ Check session byte limit (5 GB) ── exceeded → close(4003)
  │   └─ Repeat until disconnect
  │
  └─ Cleanup
      ├─ Decrement IP connection counter
      ├─ Remove from room
      └─ If room empty → delete room + event + metadata
```

### 6.3. Rate Limiting

| Parameter | Default | Description |
|-----------|---------|-------------|
| `RELAY_RATE_LIMIT` | 200 | Max new connections per IP per 60s window |
| `RELAY_MAX_CONN_PER_IP` | 50 | Max concurrent connections per IP |

Uses a sliding-window algorithm with periodic cleanup of stale IPs.

### 6.4. Backpressure / Flow Control

When the receiver's write buffer exceeds `BACKPRESSURE_HIGH` (4 MB):
1. Server pauses reading from sender
2. Waits until buffer drops below `BACKPRESSURE_LOW` (1 MB)
3. If buffer doesn't drain within `BACKPRESSURE_TIMEOUT` (30s) → warning + continue
4. Prevents server OOM when sender is faster than receiver

### 6.5. Room Management

- **Auto-cleanup**: rooms older than `ROOM_TIMEOUT` (30 min) are closed
- **Peer waiting**: uses `asyncio.Event` (no polling) — zero CPU while waiting
- **Dead connection cleanup**: before joining a room, dead WebSocket connections are removed
- **Session code hashing**: room ID = `SHA-256(session_code)[:32]`

### 6.6. Health Check

Separate HTTP server on port 8766 responds with JSON:

```json
{"status": "ok", "active_rooms": 2, "total_connections": 147}
```

Used by Docker healthcheck (every 30s) for automatic container restart if unhealthy.

### 6.7. Graceful Shutdown

On `SIGTERM` or `SIGINT`:
1. Stop accepting new connections
2. Close all active WebSocket connections with code `1001` ("server shutting down")
3. Log final statistics
4. Exit cleanly

---

## 7. Infrastructure

### 7.1. VPS (Oracle Cloud)

| Parameter | Value |
|-----------|-------|
| Provider | Oracle Cloud Infrastructure (Always Free) |
| Shape | VM.Standard.E2.1.Micro |
| CPU | 1 OCPU (AMD) |
| RAM | 1 GB |
| Storage | 50 GB boot volume |
| OS | Ubuntu 22.04 |
| Region | eu-amsterdam-1 |

### 7.2. Network Stack

```
Internet
  │
  ├─ DuckDNS (secureshare-relay.duckdns.org → VPS public IP)
  │
  ├─ Oracle Cloud Security List (ports 80, 443 open)
  │
  ├─ iptables (SYN flood protection, connection limits)
  │
  ├─ fail2ban (SSH + Caddy brute force protection)
  │
  ├─ Caddy (port 443)
  │   ├─ Auto-TLS (Let's Encrypt)
  │   ├─ Security headers (HSTS, nosniff, DENY frames)
  │   ├─ /health → static "ok" response
  │   ├─ /download/* → static file server (releases)
  │   └─ /* → reverse proxy to relay:8765
  │
  └─ Relay Server (port 8765, Docker container)
      └─ WebSocket handler
```

### 7.3. Docker Configuration

**Relay container:**
- Base image: `python:3.11-slim`
- Non-root user (`relay`)
- Read-only filesystem (`read_only: true`)
- No new privileges (`no-new-privileges:true`)
- Memory limit: 256 MB
- CPU limit: 0.5 cores
- Health check every 30s
- Auto-restart: always

**Caddy container:**
- Official `caddy:2` image
- Memory limit: 128 MB
- CPU limit: 0.25 cores
- Volumes: Caddyfile (ro), downloads (ro), data, config

### 7.4. VPS Hardening

| Mechanism | Configuration |
|-----------|--------------|
| **SSH** | Key-only authentication (password disabled) |
| **fail2ban** | SSH: 5 retries / 10 min ban; Caddy: 20 req/s / 10 min ban |
| **iptables** | SYN flood protection (`--limit 25/s`), connection limit (100/IP) |
| **Auto-updates** | `unattended-upgrades` enabled |
| **Docker hardening** | Read-only FS, no-new-privileges, resource limits |

---

## 8. CI/CD Pipeline

### 8.1. Workflow: `ci.yml` (every push)

```
Push to any branch
  │
  └─ lint-and-check (ubuntu-latest, ~25s)
      ├─ flake8 lint (app/ + server/)
      └─ Import verification (all key modules)
```

### 8.2. Workflow: `release.yml` (on `v*` tag)

```
Push tag v*
  │
  ├─ lint (ubuntu) ─────────────┐
  │                              │
  ├─ server-tests (ubuntu) ─────┤ (needs: lint)
  │   └─ 16+ tests vs live VPS  │
  │                              │
  ├─ build (windows) ───────────┤ (needs: lint)
  │   ├─ PyInstaller → .exe     │
  │   ├─ Package → .zip         │
  │   └─ Upload artifact        │
  │                              │
  ├─ release (ubuntu) ──────────┤ (needs: build + server-tests)
  │   ├─ Generate changelog     │
  │   ├─ Create GitHub Release  │
  │   └─ Attach .exe + .zip     │
  │                              │
  └─ deploy (ubuntu) ───────────┘ (needs: release)
      ├─ SCP server files to VPS
      ├─ SCP .zip to /downloads
      ├─ docker compose up --build
      └─ Health check
```

### 8.3. Release Process

```bash
# 1. Bump version in config.py + version_info.txt
# 2. Commit
git commit -am "Bump version to 3.0.4"

# 3. Tag and push
git tag v3.0.4
git push origin main --tags

# 4. GitHub Actions handles everything:
#    - Lint + test
#    - Build .exe on Windows runner
#    - Create GitHub Release with .zip + .exe
#    - Deploy updated server to VPS
#    - Upload .zip to VPS /download endpoint
```

### 8.4. Distribution

| Channel | URL | Content |
|---------|-----|---------|
| GitHub Releases | `github.com/artmarchenko/SecureShare/releases` | `.exe` + `.zip` per version |
| VPS Download | `https://secureshare-relay.duckdns.org/download/SecureShare.zip` | Latest `.zip` (always up-to-date) |

---

## 9. Configuration Reference

### 9.1. Client (`app/config.py`)

| Constant | Value | Description |
|----------|-------|-------------|
| `VPS_RELAY_URL` | `wss://secureshare-relay.duckdns.org` | Relay server WebSocket URL |
| `VPS_MAX_FILE_SIZE` | `5 * 1024^3` (5 GiB) | UI warning threshold |
| `VPS_CHUNK_SIZE` | `512 * 1024` (512 KB) | WebSocket chunk size |
| `PROTOCOL_VERSION` | `1` | Current wire protocol version |
| `MIN_PROTOCOL_VERSION` | `1` | Minimum compatible version |
| `SESSION_CODE_LENGTH` | `8` | Length of session code |
| `RESUME_MANIFEST_EXT` | `".resume"` | Resume manifest file extension |
| `RESUME_MAX_AGE` | `604800` (7 days) | Max age for resume manifests |
| `RESUME_SAVE_INTERVAL` | `64` | Save manifest every N chunks |
| `RECONNECT_MAX_RETRIES` | `5` | Max auto-reconnect attempts |
| `RECONNECT_BASE_DELAY` | `5` | Base delay (seconds, exponential backoff) |
| `RECONNECT_MAX_DELAY` | `60` | Max delay cap (seconds) |
| `APP_NAME` | `"SecureShare"` | Application name |
| `APP_VERSION` | `"3.2.0"` | Application version |

### 9.2. Server (`relay_server.py`, via env vars)

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `RELAY_HOST` | `0.0.0.0` | Listen address |
| `RELAY_PORT` | `8765` | WebSocket port |
| `RELAY_HEALTH_PORT` | `8766` | Health check HTTP port |
| `RELAY_MAX_CONN_PER_IP` | `50` | Max concurrent connections per IP |
| `RELAY_RATE_LIMIT` | `200` | Max new connections per IP per minute |
| `RELAY_ROOM_TIMEOUT` | `1800` | Room auto-cleanup (seconds) |
| `RELAY_MAX_SESSION_BYTES` | `5368709120` | Per-session data limit (5 GB) |
| `RELAY_BP_HIGH` | `4194304` | Backpressure high watermark (4 MB) |
| `RELAY_BP_LOW` | `1048576` | Backpressure low watermark (1 MB) |
| `RELAY_TRUSTED_PROXIES` | `172.16.0.0/12,...` | Trusted proxy subnets for XFF |
| `RELAY_LOG_FORMAT` | `text` | Log format: `text` or `json` |

---

## 10. Development Setup

### 10.1. Prerequisites

- Python 3.11+
- Windows 10/11 (for GUI and .exe build)
- Git

### 10.2. Clone and Install

```bash
git clone https://github.com/artmarchenko/SecureShare.git
cd SecureShare
pip install -r requirements.txt
```

### 10.3. Run from Source

```bash
# With console (see logs in real-time)
python main.py

# Without console (logs only in file)
pythonw main.py
```

### 10.4. Build .exe Locally

```bash
python build.py
# Output: dist/SecureShare.exe
```

### 10.5. Lint

```bash
pip install flake8
flake8 app/ main.py build.py server/relay_server.py
```

---

## 11. Testing

### 11.1. Server Tests

```bash
pip install websocket-client
python server/test_relay.py
```

The test suite includes 16+ tests against the **live VPS**:

| Test | What it verifies |
|------|-----------------|
| Basic relay | Two clients can exchange messages |
| Bidirectional | Messages flow in both directions |
| Binary data | Large binary payloads relay correctly |
| Multiple rooms | Independent sessions don't interfere |
| Session isolation | Client A's room can't see Client B's data |
| Peer wait | First client waits for second to join |
| Disconnect cleanup | Room is cleaned up when both disconnect |
| TLS | WSS connection with valid certificate |
| Rate limit | Rapid connections eventually get rejected |
| Room full | Third client to same room gets 4001 |
| No session code | Connection without code times out |
| Sudden disconnect | Peer disconnects mid-transfer |
| Reconnect | New session works after previous one ends |
| Throughput | Large data transfer completes successfully |
| Latency | Message round-trip time is acceptable |
| Concurrent rooms | Multiple rooms active simultaneously |

### 11.2. Client E2E Test

Manual or automated:
1. Launch two instances of the app
2. Sender selects a file, gets session code
3. Receiver enters session code
4. Both confirm verification code
5. File transfers and SHA-256 matches

---

## 12. Secrets Management

### 12.1. Local Development

Secrets are stored in `.env` file (in `.gitignore`):

```env
VPS_HOST=<ip-address>
VPS_SSH_KEY_PATH=<path-to-ssh-key>
CERT_THUMBPRINT=<certificate-thumbprint>
DUCKDNS_TOKEN=<duckdns-token>
```

### 12.2. GitHub Actions

Secrets configured in repository settings:

| Secret | Used in | Purpose |
|--------|---------|---------|
| `VPS_HOST` | `release.yml` | VPS IP address for deployment |
| `VPS_USER` | `release.yml` | SSH username on VPS |
| `VPS_SSH_KEY` | `release.yml` | Full SSH private key for VPS access |
| `CERT_THUMBPRINT` | *(future)* | Code signing certificate |
| `DUCKDNS_TOKEN` | *(future)* | DuckDNS API token for IP updates |
| `GITHUB_TOKEN` | `release.yml` | Auto-provided for GitHub Release creation |

### 12.3. Rules

1. **Never** hardcode secrets in source files
2. Use `os.environ["KEY"]` or `${{ secrets.KEY }}` for access
3. Use `<PLACEHOLDER>` in documentation and examples
4. `.env` is in `.gitignore` — never committed

---

## 13. Known Limitations

| Limitation | Reason | Workaround |
|-----------|--------|------------|
| **5 GB per session** | Server-enforced to prevent abuse on free VPS | Split large files; use archives |
| **One file per session** | Protocol design for simplicity | Use ZIP/TAR for multiple files |
| **Windows only** | CustomTkinter + PyInstaller target Windows | Run from source on macOS/Linux |
| **Single relay server** | Architecture choice | Can deploy additional relays |
| **No offline mode** | Relay-dependent architecture | Both users must be online |

---

## 14. Threat Model

### 14.1. What the Server Can See

| Data | Visible? | Notes |
|------|----------|-------|
| Client IP addresses | ✅ Yes | Needed for rate limiting |
| Session code | ❌ No | Only SHA-256 hash stored in memory |
| Public keys | ❌ No | Encrypted with signaling key |
| File content | ❌ No | E2E encrypted (AES-256-GCM) |
| File name/size | ❌ No | Encrypted in control frames |
| Number of bytes relayed | ✅ Yes | Needed for session limit |
| Connection timestamps | ✅ Yes | Standard logging |

### 14.2. Attack Scenarios

| Attack | Protection | Residual Risk |
|--------|-----------|---------------|
| **MITM (key substitution)** | Signaling encryption + verification code | User must actually compare codes |
| **Replay attack** | Counter-based nonces + session AAD | None if protocol followed |
| **Session hijacking** | Session code brute force: 36^8 ≈ 2.8 × 10^12 combinations | Impractical within session lifetime |
| **DDoS on relay** | Rate limiting + fail2ban + iptables SYN protection | Oracle Free tier has limited bandwidth |
| **Server compromise** | E2E encryption — server never has keys | Attacker could disrupt but not decrypt |
| **.exe decompilation** | Python bytecode visible; no secrets in binary | Relay URL, protocol visible; no secret keys |
| **DNS spoofing** | TLS certificate pinning via Let's Encrypt | User trusts CA infrastructure |

### 14.3. What an Attacker with the .exe Can Learn

| Extractable | Not Extractable |
|------------|----------------|
| Relay server URL (`wss://...`) | SSH keys to VPS |
| Protocol version and wire format | Private encryption keys (generated per session) |
| Encryption algorithms used | Session codes of other users |
| Application version | Any transferred file content |

---

*Last updated: February 2026 · v3.2*
