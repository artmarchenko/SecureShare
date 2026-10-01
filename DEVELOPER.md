# SecureShare — Developer Guide

> Comprehensive technical documentation for developers, auditors, and contributors.
>
> **Version:** 4.0.0 · **Protocol:** v2 · **Architecture:** E2E encrypted, relay-based · **Author:** Artem Marchenko

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
| **Single binary** | Distributed as a standalone `.exe` (Win) or binary (Linux) — no installation needed |
| **Ephemeral sessions** | Relay rooms exist only while both peers are connected (auto-expire after 30 min) |
| **Defense in depth** | TLS + E2E encryption + commit-then-reveal verification + signed updates |

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
│  • HSTS, X-Content-Type-Options, X-Frame-Options, Permissions-Policy   │
│  • Auto X-Forwarded-For (real client IP)                               │
│  • /           → Landing page (static files from /www)                 │
│  • /health     → Relay health check (proxy to relay:8766)              │
│  • /api/*      → API endpoints (proxy to relay:8766)                   │
│  • /admin      → Admin dashboard (static from /www)                    │
│  • /download/* → Static file server (.zip/.tar.gz releases)            │
│  • @websocket  → WebSocket relay (proxy to relay:8765)                 │
│  Port 443 (HTTPS/WSS) ──────────────► Port 8765 (WS) / 8766 (HTTP)   │
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
│  • Health check + API on :8766                                         │
│  • Analytics & crash report collection (JSONL persistence)             │
│  • Graceful shutdown (SIGTERM/SIGINT)                                  │
│  Port 8765 (WS) + Port 8766 (HTTP health + API)                       │
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
| CI/CD | GitHub Actions | Lint, Test, Build, Release, Deploy (4 workflows) |

### Project Structure

```
fileshare/
├── app/                          # Client application
│   ├── __init__.py
│   ├── config.py                 # Constants: URLs, limits, version, protocol
│   ├── crypto_utils.py           # Protocol v2 crypto: scrypt/HKDF secrets, X25519, AES-GCM, commitments
│   ├── ws_relay.py               # Sender/receiver: handshake, transfer, resume, auto-reconnect
│   ├── gui.py                    # Main window + send/receive workflows
│   ├── ui/                       # Dialogs: verify, diagnostics, update, help
│   ├── diagnostics.py            # Connectivity checks (no GUI)
│   ├── format.py                 # Human-readable sizes/speeds/ETA
│   ├── i18n.py + lang/*.json     # uk / en / de
│   ├── updater.py                # Auto-update: signed checksums, download, verify, install
│   ├── telemetry.py              # Crash reports (default on) + transfer stats (opt-in)
│   └── selftest.py               # `--self-test` for packaged builds
│
├── server/                       # Relay server (deployed to VPS)
│   ├── relay_server.py           # Async WebSocket relay + HTTP API (Python + websockets)
│   ├── analytics.py              # Server-side analytics, crash store, rate limiting
│   ├── Dockerfile                # Docker image (python:3.11-slim, non-root)
│   ├── docker-compose.yml        # Services: relay + caddy + volumes
│   ├── Caddyfile                 # Reverse proxy + auto-TLS + security headers
│   ├── requirements.txt          # Server dependencies (websockets)
│   ├── test_relay.py             # Live smoke tests against the production relay
│   ├── DEPLOY.md                 # Manual deployment guide
│   └── www/                      # Static web content (mounted in Caddy)
│       ├── index.html            # Landing page
│       └── admin.html            # Admin dashboard (stats, crashes, logs)
│
├── assets/                       # Application assets
│   ├── SecureShare.png           # Logo (1024×1024 RGBA)
│   ├── SecureShare.ico           # Multi-size icon (16–256px)
│   └── icon_32.png               # 32×32 icon for window/taskbar
│
├── tests/                        # pytest: unit, server, integration, adversarial, ui
├── scripts/                      # regression_guard, release_signing, ui_screenshots
├── .github/workflows/            # CI/CD
│   ├── ci.yml                    # Lint + guard + import check
│   ├── tests.yml                 # pytest on Windows + Linux, UI screenshots
│   ├── release.yml               # Build Win+Linux + GitHub Release (on v* tag)
│   ├── deploy-web.yml            # Deploy landing page (on push to server/www/)
│   └── deploy-server.yml         # Deploy relay server (on push to server/*.py)
│
├── main.py                       # Entry point (logging setup + crash handler)
├── build.py                      # PyInstaller build script (Win + Linux)
├── SecureShare.spec              # PyInstaller spec — Windows
├── SecureShare-linux.spec        # PyInstaller spec — Linux
├── version_info.txt              # Windows .exe metadata (version, publisher)
├── requirements.txt              # Client Python dependencies
├── LICENSE                       # MIT License
├── .flake8                       # Linter configuration
├── .gitignore                    # Git ignore rules
└── .env                          # Local secrets (not in repo)
```

---

## 3. Security Model

The design goal is that a **compromised relay** (VPS, Caddy, TLS termination —
anyone in the middle of the WebSocket) can disrupt transfers but can neither
read nor undetectably modify them, provided the two users compare the
verification code.

### 3.1. Layers

```
Layer 3:  TLS 1.2+ (transport) ───── client ↔ Caddy
Layer 2:  Signaling encryption ───── key from the session code (scrypt)
Layer 1:  E2E encryption ─────────── X25519 + AES-256-GCM, commit-then-reveal
```

The relay only ever holds `room_id` (derived from the code) and ciphertext.

### 3.2. Cryptographic Algorithms (protocol v2, since 4.0)

| Component | Algorithm | Notes |
|-----------|-----------|-------|
| Code → master secret | scrypt (N=2¹⁵, r=8, p=1), salt `secureshare-p2\|code` | ~0.1 s / 32 MiB once per transfer; makes offline guessing expensive |
| Room ID | HKDF-SHA256(master, `…\|room`) → 16 bytes hex | the only thing the relay sees |
| Signaling key | HKDF-SHA256(master, `…\|signaling`) | AES-256-GCM, random nonce |
| Key exchange | X25519 | fresh key pair per connection |
| Commitment | SHA-256(`…\|commit` ‖ sender_pub ‖ 32-byte opening) | sender commits before seeing the receiver's key |
| Data key | HKDF-SHA256(DH secret, salt = master, info = `…\|data-key\|` ‖ transcript) | transcript = sender_pub ‖ receiver_pub |
| Verification code | HKDF(data key, `…\|sas\|` ‖ transcript) → 5 bytes → base32 `XXXX-XXXX` | 40 bits |
| Data encryption | AES-256-GCM | nonce = role prefix (sender 0, receiver 1) ‖ 64-bit counter |
| Reconnect proof | HMAC-SHA256(previous data key, `…\|reconnect\|` ‖ author role ‖ new transcript) | replaces the v1 bearer token |
| Integrity | SHA-256 of the whole file | checked after the last chunk |
| Update trust | Ed25519 signature over `SHA256SUMS.txt` | see 12.3 |

### 3.3. Why Commit-then-Reveal

With a short authentication string (the verification code), a relay that
substitutes keys could otherwise try many fake key pairs until both users see
the same code (v1: 32-bit code, ~2¹⁶ attempts per side — under a second).
In v2 the sender publishes `commit = H(sender_pub ‖ opening)` first, the
receiver answers with its key, and only then the sender reveals its key.
A relay must fix its substitute keys before it learns the honest ones, so it
gets **one blind guess**: success probability 2⁻⁴⁰. A revealed key that does
not match the commitment aborts the transfer (`relay_commit_mismatch`) without
asking the user and without retrying.

### 3.4. Verification

Both sides show the 8-character code (base32 letters A–Z and digits 2–7, e.g.
`K7PQ-2XMA`). Users compare it over another channel (voice, messenger) and
confirm; either side can reject, which aborts both. Unanswered dialogs close
after `VERIFY_TIMEOUT` (120 s).

### 3.5. Associated Data (AAD)

Every E2E frame binds: room ID ‖ **author role** ‖ frame type (`C` control,
`D` data) ‖ for data frames the 4-byte chunk number. Consequences:
- a frame cannot be moved to another session (room ID);
- a frame reflected back to its author fails (author role);
- chunks cannot be relabelled or reordered (chunk number).

### 3.6. Reconnect Without Re-verification

After a verified session each side keeps that session's key. On reconnect the
new key exchange runs as usual, then both send a `session_proof`: an HMAC
under the **previous** key over the **new** public keys and the author role.
If the peer's proof verifies, the code is not asked again. A proof observed
by the relay is useless in any other key exchange (different public keys) and
cannot be reflected (role). On the first connection the proof is empty.

### 3.7. File Integrity

After all chunks arrive the receiver hashes the `.part` file and compares it
with the sender's SHA-256 (sent inside the encrypted channel); on mismatch
the partial file is deleted.

---

## 4. Wire Protocol

### 4.1. Frame Format

Every WebSocket message has a 1-byte type prefix; the very first text message
of a connection is the room ID.

| Type | Hex | Payload |
|------|-----|---------|
| `S` | `0x53` | `nonce(12) ‖ AES-GCM(signaling_key, JSON)` |
| `C` | `0x43` | `nonce(12) ‖ AES-GCM(data_key, JSON, aad=…‖role‖C)` |
| `D` | `0x44` | `seq(4, BE) ‖ nonce(12) ‖ AES-GCM(data_key, flag‖zlib?(chunk), aad=…‖role‖D‖seq)` |

Data chunks are 512 KiB; `flag` = `0x01` if zlib (level 1) saved more than
64 bytes, else `0x00` + raw bytes.

### 4.2. Handshake (signaling, JSON)

```
Sender                              Relay                    Receiver
  │── room_id (text) ────────────────►│◄──────── room_id ───────│   paired by SHA-256(room_id)
  │── S {commit, protocol_version, app_version} ──────────────►│
  │◄──────────────── S {pub_key: receiver_pub, versions} ───────│
  │── S {reveal: sender_pub, opening} ────────────────────────►│   receiver checks commitment
  │── S {session_proof: mac|null} ────────────────────────────►│
  │◄──────────────────────────────── S {session_proof} ────────│
  │   both: data key, verification code                        │
  │── S {verified | verify_reject} ◄──────────────────────────►│   (auto on valid proof)
```

Version check: every first message carries `protocol_version`; a peer below
`MIN_PROTOCOL_VERSION` (= 2) or above ours is refused for good. v1 clients
(≤ 3.x) send the raw code as room name, so they never meet a v2 client — a v2
client whose peer never arrives shows `relay_peer_version_hint`.

### 4.3. Control Messages (`C`)

| Type | Direction | Fields |
|------|-----------|--------|
| `relay_meta` | S → R | `name`, `size`, `sha256`, `chunk_size`, `total_chunks`, `transfer_id` |
| `relay_meta_ack` | R → S | `resume` (bool, opt), `received_chunks` (list, opt) |
| `relay_done` | S → R | `sha256`, `total_chunks` (must equal the validated value) |
| `relay_retransmit` | R → S | `missing` (≤ 1000 chunk numbers per message) |
| `relay_done_ack` | R → S | `verified` (bool) |

Receiver-side validation of `relay_meta`: the name is reduced to its last
component (`/` and `\` on every OS), `: * ? " < > |` and control characters
become `_`, reserved Windows device names get a `_` prefix; size must be a
positive int ≤ 5 GiB; unreasonable `chunk_size` falls back to 512 KiB;
`total_chunks` is recomputed from the size. An existing file is never
overwritten — the new one is saved as `name (1).ext`, `name (2).ext`, …

### 4.4. Sequence

```
Sender                         Relay                        Receiver
  │── C relay_meta ───────────────►│──────────────────────────────►│
  │◄──────────────────────────────│◄──── C relay_meta_ack (+resume)│
  │── D chunk 0..N ───────────────►│──────────────────────────────►│  (disk writes on a background thread)
  │── C relay_done ───────────────►│──────────────────────────────►│
  │◄──────────────────────────────│◄──── C relay_retransmit [..]   │  (if chunks missing, ≤ 5 rounds)
  │◄──────────────────────────────│◄──── C relay_done_ack(verified)│
```

### 4.5. Resume

The receiver keeps `<name>.part` plus `<name>.part.resume` (JSON: transfer id =
SHA-256(name|size|sha256)[:32], chunk size, received chunk list, timestamp),
saved every 64 chunks and on interruption. A later transfer of the same file
(any session code) with a matching transfer id reuses the `.part`; the ACK
lists the chunks the sender can skip. Manifests expire after 7 days.

### 4.6. Auto-Reconnect

On connection loss during a transfer both sides reconnect with exponential
backoff (5, 10, 20, 40, 60 s; up to 5 attempts; Cancel interrupts the wait),
redo the handshake (with session proofs → no dialog) and continue via resume.
Attempts end as `SUCCESS`, `FATAL` (cancel, rejected code, invalid data,
commitment mismatch, incompatible version) or `RETRY` (connection-level).

---

## 5. Client Application

### 5.1. Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `crypto_utils.py` | Session secrets from the code, commitments, `CryptoSession` (keys, SAS, AAD, reconnect proofs) |
| `ws_relay.py` | `_RelayPeer` (reconnect loop, handshake, cancel), `VPSRelaySender`, `VPSRelayReceiver` (`_on_meta` / `_on_data` / `_on_done`, `_DiskWriter`), typed `TransferState` |
| `gui.py` | Main window, send/receive workflows; state indicator driven by `on_state` |
| `ui/*.py` | Verification, diagnostics (+ privacy switches), update and help windows |
| `diagnostics.py` | Internet (1.1.1.1:443), DNS, TLS, WebSocket (HTTPS fallback), latency |
| `updater.py` | GitHub Releases check, signed-checksum verification, extraction, install |
| `telemetry.py` | Anonymous crash reports (default on) and transfer stats (opt-in) |

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
| Diagnostics | 5-point connectivity check + privacy switches (crash reports, transfer statistics) |
| Auto-update check | Silent check on startup + manual "🔄" button; download, verify SHA-256, rename→copy→launch |
| Donate button | "❤️" button opens Ko-fi donation page |
| Privacy switches | Crash reports (default **on**) and transfer statistics (default off) in Diagnostics |
| Same-name files | Never overwritten; saved as `name (1).ext` |
| Verification timeout | Unanswered code dialog closes after 120 s |
| Startup tips | Random informational/motivational messages on launch |
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
- **Stateless relay**: session state is in-memory; analytics/crashes persist to JSONL on disk
- **No session codes**: clients send a room ID derived from the code (scrypt + HKDF); the relay keys rooms by `SHA-256(room_id)[:32]`
- **No IPs in logs**: log lines carry a daily-salted hash tag; IPs are only used in memory for rate limiting

### 6.2. Connection Lifecycle

```
Client connects (WSS)
  │
  ├─ Rate limit check (per IP) ── fail → close(4029)
  │
  ├─ Receive room ID (15s timeout) ── timeout → close
  │
  ├─ Hash room ID → room key
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
| Outbound transfer quota | Up to 10 TB/month egress (Oracle Always Free) |
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
- Read-only filesystem (`read_only: true`) with writable `/data` volume for analytics
- No new privileges (`no-new-privileges:true`)
- Memory limit: 256 MB
- CPU limit: 0.5 cores
- Health check every 30s
- Auto-restart: always

**Caddy container:**
- Official `caddy:2` image
- Memory limit: 128 MB
- CPU limit: 0.25 cores
- Volumes: Caddyfile (ro), downloads (ro), www (ro), data, config

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

The project uses **4 independent GitHub Actions workflows**, each targeting a specific deployment scope to minimize downtime and avoid unnecessary rebuilds. All VPS-targeting workflows share a `concurrency: vps-deploy` group to prevent race conditions.

### 8.1. Workflow: `ci.yml` (on push to app code)

```
Push to main (app/**, main.py, build.py, server/*.py)
  │
  └─ lint (ubuntu-latest, ~1 min)
      ├─ flake8 lint (app/ + server/)
      └─ Import verification (all key modules)
```

### 8.1b. Workflow: `tests.yml` (push / PR)

pytest on `ubuntu-latest` (xvfb) and `windows-latest` with coverage `fail_under=75`, plus a
`screenshots` job that uploads UI screenshots (3 languages × 5 screens) as artifacts.
Also called by `release.yml` as a gate before building.

### 8.2. Workflow: `release.yml` (on `v*` tag)

```
Push tag v*
  │
  ├─ lint (ubuntu) ─────────────┐
  │                              │
  ├─ server-tests (ubuntu) ─────┤ (needs: lint)
  │   └─ live smoke tests (VPS) │
  │                              │
  ├─ build (windows) ───────────┤ (needs: lint)
  │   ├─ PyInstaller → .exe     │
  │   ├─ Package → .zip         │
  │   └─ Upload artifact        │
  │                              │
  ├─ build-linux (ubuntu) ──────┤ (needs: lint)
  │   ├─ PyInstaller → binary   │
  │   ├─ Package → .tar.gz      │
  │   └─ Upload artifact        │
  │                              │
  ├─ release (ubuntu) ──────────┤ (needs: build + build-linux + server-tests)
  │   ├─ Generate SHA256SUMS    │
  │   ├─ Sign it (Ed25519)      │
  │   ├─ Generate changelog     │
  │   ├─ Create GitHub Release  │
  │   └─ Attach Win + Linux     │
  │                              │
  └─ upload-binaries (ubuntu) ──┘ (needs: release, NO relay restart)
      ├─ SCP .zip to /downloads
      ├─ SCP .tar.gz to /downloads
      └─ Verify download URLs
```

**Note:** `release.yml` does NOT restart the relay server. It only uploads client binaries to the VPS `/downloads` directory.

### 8.3. Workflow: `deploy-web.yml` (on push to `server/www/**`)

```
Push to main (server/www/**)
  │
  └─ deploy-web (ubuntu, ~30s)
      ├─ SCP static files to VPS /www
      ├─ Verify landing page (HTTP 200)
      └─ Verify relay NOT restarted (zero downtime)
```

### 8.4. Workflow: `deploy-server.yml` (on push to server code)

```
Push to main (server/*.py, Dockerfile, docker-compose.yml, Caddyfile)
  │
  └─ deploy-server (ubuntu, ~2-3 min)
      ├─ Detect what changed
      ├─ SCP server files to VPS
      ├─ IF relay code changed → docker compose build + restart relay
      ├─ IF Caddyfile changed → caddy reload (or restart)
      ├─ IF docker-compose.yml changed → full docker compose up
      └─ Health check
```

### 8.5. Release Process

Prerequisite: the `RELEASE_SIGNING_KEY` secret is set (12.3) — otherwise the
release job fails on purpose.

```bash
# 1. Bump the version in all three places (the regression guard checks they match):
#    app/config.py APP_VERSION, version_info.txt (filevers/prodvers + strings),
#    server/relay_server.py RELAY_LATEST_VERSION default
# 2. Update CHANGELOG.md, open a PR, wait for CI, merge.
#    Merging touches server/relay_server.py → deploy-server.yml rebuilds and
#    restarts the relay (a few seconds). Check /health active_rooms first.
# 3. Tag and push
git tag v4.0.0
git push origin v4.0.0

# 4. release.yml: lint + guard → full test suite (Windows + Linux) → build
#    .exe and Linux binary → --self-test on both → SHA256SUMS.txt → Ed25519
#    signature → GitHub Release (+ .sig) → binaries to the VPS
```

### 8.6. Distribution

| Channel | URL | Content |
|---------|-----|---------|
| GitHub Releases | `github.com/artmarchenko/SecureShare/releases` | `.exe` + `.zip` + `.tar.gz` per version |
| VPS Download (Win) | `https://secureshare-relay.duckdns.org/download/SecureShare.zip` | Latest Windows `.zip` |
| VPS Download (Linux) | `https://secureshare-relay.duckdns.org/download/SecureShare-linux-x64.tar.gz` | Latest Linux `.tar.gz` |

---

## 9. Configuration Reference

### 9.1. Client (`app/config.py`)

| Constant | Value | Description |
|----------|-------|-------------|
| `VPS_RELAY_URL` | `wss://secureshare-relay.duckdns.org` | Relay server WebSocket URL |
| `VPS_MAX_FILE_SIZE` | `5 * 1024^3` (5 GiB) | UI warning threshold |
| `VPS_CHUNK_SIZE` | `512 * 1024` (512 KB) | WebSocket chunk size |
| `PROTOCOL_VERSION` | `2` | Current wire protocol version |
| `MIN_PROTOCOL_VERSION` | `2` | Minimum compatible version (v1 refused) |
| `SESSION_CODE_LENGTH` | `8` | Length of session code |
| `RESUME_MANIFEST_EXT` | `".resume"` | Resume manifest file extension |
| `RESUME_MAX_AGE` | `604800` (7 days) | Max age for resume manifests |
| `RESUME_SAVE_INTERVAL` | `64` | Save manifest every N chunks |
| `RECONNECT_MAX_RETRIES` | `5` | Max auto-reconnect attempts |
| `RECONNECT_BASE_DELAY` | `5` | Base delay (seconds, exponential backoff) |
| `RECONNECT_MAX_DELAY` | `60` | Max delay cap (seconds) |
| `APP_NAME` | `"SecureShare"` | Application name |
| `APP_VERSION` | `"4.0.0"` | Application version |
| `HOMEPAGE_URL` | `"https://secureshare-relay.duckdns.org"` | Landing page URL |
| `DONATE_URL` | `"https://ko-fi.com/secureshare"` | Donation page URL |
| `GITHUB_URL` | `"https://github.com/artmarchenko/SecureShare"` | GitHub repository URL |

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
| `RELAY_DATA_DIR` | `/data` | Directory for analytics JSONL persistence |
| `RELAY_ADMIN_KEY` | *(none)* | Secret key for admin API access |
| `RELAY_LATEST_VERSION` | `"4.0.0"` | Reported as latest client version via `/api/version` (landing page only; the app asks GitHub) |
| `TELEGRAM_BOT_TOKEN` | *(none)* | Telegram bot token for critical alerts |
| `TELEGRAM_CHAT_ID` | *(none)* | Telegram chat ID for critical alerts |

---

## 10. Development Setup

### 10.1. Prerequisites

- Python 3.11+
- Windows 10/11 or Linux (64-bit)
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
flake8 app/ main.py build.py
flake8 server/relay_server.py
```

### 10.6. Worktree Convention (Required)

To avoid branch/worktree chaos, follow this operational protocol:

1. **One task = one branch = one worktree**
   - Branch naming: `feature/*`, `hotfix/*`, `chore/*`
   - Never use detached `HEAD` for work that will be committed.
2. **Keep one canonical `main` worktree**
   - Use a single stable folder for `main`.
   - Keep it synced with `origin/main`.
3. **Before any commit/push, always verify context**
   - `git rev-parse --abbrev-ref HEAD`
   - `git status -sb`
   - If branch name is `HEAD`, stop and switch to a real branch.
4. **After merge, clean up immediately**
   - Delete remote branch
   - Delete local branch
   - Remove corresponding worktree
5. **Weekly repository hygiene**
   - `git fetch --all --prune`
   - `git worktree list`
   - `git branch -vv`
   - Remove stale or gone branches/worktrees.

Recommended command flow:

```bash
# Start task
git fetch origin
git switch -c hotfix/example origin/main
git worktree add ../wt-hotfix-example hotfix/example

# Finish task (after merge)
git push origin --delete hotfix/example
git branch -D hotfix/example
git worktree remove ../wt-hotfix-example
git worktree prune
```

---

## 11. Testing

### 11.0. Automated Test Suite (pytest)

```bash
pip install -r requirements-dev.txt
python -m pytest                       # everything (~1.5 min)
python -m pytest -m unit               # fast unit tests (~1 s)
python -m pytest -m "integration or adversarial"
python -m pytest -m ui                 # GUI tests (need a display; Linux CI uses xvfb-run)
python -m pytest --cov --cov-report=term
```

| Layer | Folder | What it covers |
|-------|--------|----------------|
| unit | `tests/unit/` | crypto, wire helpers, resume manifest, i18n, updater (malicious archives, fake CDN), telemetry privacy |
| server | `tests/server/` | HTTP API, rate limiting, admin auth, analytics persistence |
| integration | `tests/integration/` | real sender/receiver through the repo's relay started in-process on loopback: sizes, cancel, resume, auto-reconnect |
| adversarial | `tests/adversarial/` | receiver input validation against a scripted peer (path traversal, bad sizes, retransmit, garbage frames) |
| ui | `tests/ui/` | the real CustomTkinter window driven programmatically, incl. full transfers through the GUI |

Safety: `tests/conftest.py` redirects `APPDATA` to a temp dir and blocks every
non-loopback connection, so tests never touch real settings, production or GitHub.
Known defects are recorded as `xfail(strict=True)` with the finding ID from
`REMEDIATION_PLAN.md`; when a fix lands the test flips and the marker must be removed.

CI: `.github/workflows/tests.yml` (Windows + Linux) runs on every push/PR and
gates `release.yml` builds. Coverage threshold: `.coveragerc` (`fail_under`).

### 11.0a. Protocol Test Vectors (for other implementations)

`tests/vectors/protocol_v2.json` pins every derived value of protocol v2 —
session secrets from codes, keys and verification code for fixed X25519 keys,
commitment, reconnect proofs, encrypted control/data frames, a signaling
frame, transfer IDs and file-name sanitising. Other clients (the Android app)
must reproduce them byte for byte; `tests/unit/test_protocol_vectors.py`
keeps the file in sync with `app/`. Regenerate after an intentional protocol
change with `python scripts/protocol_vectors.py`.

### 11.0b. Command-Line Client

```bash
python -m app.cli send report.pdf                 # prints CODE: xxxx-xxxx, then VERIFY: XXXX-XXXX
python -m app.cli receive xxxx-xxxx --out ~/Downloads
python -m app.cli --relay ws://127.0.0.1:8765 --yes send f.bin --code test-0001   # tests / local relay
```

Same transfer code as the desktop app, no GUI. `--yes` skips the verification
prompt — only for tests or two machines you control. Exit codes: 0 ok, 1
failed/rejected, 2 usage, 130 interrupted.

### 11.1. Live Server Smoke Tests

```bash
pip install websocket-client
python server/test_relay.py
```

This script runs 15 checks against the **live VPS**:

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

### 11.3. Cross-Module Regression Guard (Required Before Push)

Run this guard before any push to avoid breaking previously tested behavior
in another part of the project:

```bash
python scripts/regression_guard.py
```

What it checks:
- Version sync across `app/config.py`, `version_info.txt`, `server/relay_server.py`
- Server invariants (`/health` active_rooms guard + analytics restore on startup)
- Landing i18n invariants (language buttons + `en/de` key coverage for all `data-i18n`)
- App i18n: every `app/lang/*.json` is valid, same keys and same `{placeholders}` in all languages

The pre-push hook also runs the fast unit tests (`pytest -m unit`).

Optional: enforce automatically via Git hook:

```bash
git config core.hooksPath .githooks
```

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
| `VPS_HOST` | all deploy workflows | VPS IP address for deployment |
| `VPS_USER` | all deploy workflows | SSH username on VPS |
| `VPS_SSH_KEY` | all deploy workflows | Full SSH private key for VPS access |
| `RELEASE_SIGNING_KEY` | `release.yml` | Ed25519 key that signs `SHA256SUMS.txt` (see 12.3) |
| `CERT_THUMBPRINT` | *(future)* | Code signing certificate |
| `DUCKDNS_TOKEN` | *(future)* | DuckDNS API token for IP updates |
| `GITHUB_TOKEN` | `release.yml` | Auto-provided for GitHub Release creation |

### 12.3. Release Signing (auto-update trust)

The auto-updater installs an update only if `SHA256SUMS.txt` carries a valid
Ed25519 signature (`SHA256SUMS.txt.sig`) from a key listed in
`app/updater.py` → `TRUSTED_RELEASE_KEYS`, and the archive is listed in it.
A compromised GitHub account or CDN therefore cannot push an update.

| Key | Private half | Public half |
|-----|--------------|-------------|
| primary | GitHub secret `RELEASE_SIGNING_KEY` only | in `TRUSTED_RELEASE_KEYS` |
| backup | offline with the maintainer (password manager / USB), never in the repo or CI | in `TRUSTED_RELEASE_KEYS` |

- CI signs in `release.yml` (`scripts/release_signing.py sign`) and fails if the
  secret is missing or is not one of the embedded keys.
- Verify any release by hand: `python scripts/release_signing.py verify SHA256SUMS.txt SHA256SUMS.txt.sig`
- **Rotation (primary lost or leaked):** put the *backup* private key into
  `RELEASE_SIGNING_KEY`, generate a new pair
  (`python scripts/release_signing.py generate <file>`), replace the old
  primary in `TRUSTED_RELEASE_KEYS` with the new public key (keep the
  backup's), release. Installed clients accept that release via the backup
  key; later releases can go back to being signed with the new primary.

### 12.4. Rules

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
| **4.x ↔ 3.x incompatible** | Protocol v2 cannot be downgraded safely | Both sides need 4.0+ |
| **Windows & Linux** | macOS not officially supported | Run from source on macOS |
| **Single relay server** | Architecture choice | Can deploy additional relays |
| **No offline mode** | Relay-dependent architecture | Both users must be online |

---

## 14. Threat Model

### 14.1. What the Relay (or Whoever Controls It) Can See

| Data | Visible? | Notes |
|------|----------|-------|
| Client IP addresses | ✅ in memory | rate limiting; log lines carry a daily-salted hash tag, not the IP |
| Session code | ❌ | only `room_id` = HKDF(scrypt(code)); guessing the code from it costs one scrypt per guess |
| Public keys, verification messages | ❌ | encrypted with the code-derived signaling key |
| File content, name, size, hash | ❌ | E2E encrypted control/data frames |
| Amount of data, timing, room pairing | ✅ | needed to relay and enforce the 5 GB limit |

### 14.2. Attack Scenarios

| Attack | Protection | Residual risk |
|--------|-----------|---------------|
| **Relay substitutes keys (MITM)** | commit-then-reveal + 40-bit verification code bound to both keys | 2⁻⁴⁰ per attempt — **only if users actually compare the code** |
| **Relay forces a reconnect and replays a token** | reconnect proof = MAC under the previous key over the new public keys and role | none known |
| **Relay reorders, moves or reflects frames** | AAD: room ‖ author role ‖ frame type ‖ chunk number | transfer can be disrupted, not altered |
| **Relay learns the session code** | code never sent; scrypt-derived room ID | offline guessing of a 36⁸ code space at one scrypt per guess |
| **Malicious peer sends bad metadata** | name sanitising, size/chunk validation, no overwrite, SHA-256 check | — |
| **Compromised GitHub account / CDN pushes an update** | Ed25519-signed `SHA256SUMS.txt`, fail-closed updater | theft of the signing key (primary in CI secret, backup offline) |
| **DDoS on the relay** | rate limiting, fail2ban, iptables SYN limits | service availability; Oracle egress quota (10 TB/month) |
| **Server compromise** | E2E encryption; relay holds no keys | can disrupt, cannot decrypt |
| **Reverse engineering the .exe** | no secrets in the binary | relay URL and protocol are public by design |

### 14.3. Not Protected Against

- Users who confirm the verification code without comparing it.
- Malware on either user's computer.
- Traffic analysis (who talks to the relay when, and how much).

---

*Last updated: October 2026 · v4.0.0 · protocol v2*
