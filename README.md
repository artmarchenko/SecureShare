# SecureShare

**Secure end-to-end encrypted file sharing** — a standalone .exe for transferring files securely between two computers over the internet.

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-3.3.1-green)

## What is it

SecureShare is a desktop application with a graphical interface for one-time secure file transfers between two users. No registration, no network configuration, no white IP addresses required.

### Key Features

- **End-to-End Encryption** — X25519 (ECDH) + AES-256-GCM
- **VPS Relay** — dedicated relay server with automatic TLS (Let's Encrypt)
- **MITM Verification** — visual security code comparison
- **SHA-256 Integrity** — hash verification after transfer
- **Auto-Reconnect & Resume** — transfers survive network interruptions
- **Auto-Update** — checks for new versions on startup with SHA-256 verification
- **Built-in Diagnostics** — connectivity and server health checks
- **Cross-platform** — Windows (.exe) and Linux binaries; no installation needed
- **5 GB session limit** — per-session data transfer cap

## How to Use

### Sender

1. Launch `SecureShare.exe`
2. Select a file
3. Click "Send" — a session code will be generated (e.g. `a7f3-bc21`)
4. Share the session code with the receiver
5. Compare the verification code
6. Wait for the transfer to complete

### Receiver

1. Launch `SecureShare.exe`
2. Enter the session code from the sender
3. Choose a save directory
4. Click "Receive"
5. Compare the verification code
6. Wait for the file to be saved

## How It Works

```
Sender                          VPS Relay                     Receiver
  |                               |                              |
  |-- 1. Connect (WSS) --------->|                              |
  |                               |<-------- Connect (WSS) -----|
  |                               |                              |
  |-- 2. X25519 key exchange --->|--- relay encrypted bytes --->|
  |<- (derive shared AES key) ---|--- relay encrypted bytes ---|
  |                               |                              |
  |-- 3. Verification code ----->|                              |
  |   (user confirms match)      |    (user confirms match)     |
  |                               |                              |
  |-- 4. E2E encrypted file ====>|====== relay raw bytes =====>|
  |   AES-256-GCM chunks         |                              |
  |                               |                              |
  |-- 5. SHA-256 verify -------->|<------- SHA-256 result ------|
  |                               |                              |
```

### Architecture

| Component | Technology | Purpose |
|-----------|------------|---------|
| Client | Python + CustomTkinter | GUI, encryption, transfer logic |
| Relay Server | Python + websockets | Session management, byte relay |
| TLS | Caddy + Let's Encrypt | Automatic HTTPS/WSS |
| Hosting | Oracle Cloud (ARM VM) | Free-tier VPS |
| DNS | DuckDNS | Free dynamic DNS |

## Development

### Requirements

- Python 3.11+
- Windows 10/11 or Linux (64-bit)

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run from Source

```bash
python main.py
```

### Build

```bash
python build.py
```

Result: `dist/SecureShare.exe` (Windows) or `dist/SecureShare` (Linux)

## Project Structure

```
fileshare/
├── app/
│   ├── config.py          # Configuration (VPS URL, limits, version, links)
│   ├── crypto_utils.py    # X25519, AES-256-GCM, HKDF, signaling crypto
│   ├── gui.py             # CustomTkinter GUI + transfer orchestration
│   ├── ws_relay.py        # VPS WebSocket relay sender/receiver
│   ├── updater.py         # Auto-update: check, download, verify, install
│   └── telemetry.py       # Crash reports + anonymous analytics (opt-in)
├── server/
│   ├── relay_server.py    # VPS relay server + HTTP API (Python + websockets)
│   ├── analytics.py       # Analytics, crash store, rate limiting
│   ├── Dockerfile         # Docker image for relay server
│   ├── docker-compose.yml # Docker Compose (relay + Caddy)
│   ├── Caddyfile          # Caddy reverse proxy + auto-TLS
│   ├── test_relay.py      # Server test suite (16+ tests)
│   ├── DEPLOY.md          # Deployment instructions (Oracle Cloud)
│   └── www/               # Landing page + admin dashboard
├── main.py                # Entry point
├── build.py               # PyInstaller build script (Win + Linux)
├── requirements.txt       # Python dependencies
├── SecureShare.spec       # PyInstaller spec (Windows)
├── SecureShare-linux.spec # PyInstaller spec (Linux)
├── version_info.txt       # .exe metadata (version, publisher)
└── LICENSE                # MIT License
```

## Security

### Cryptography

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Key Exchange | X25519 (ECDH) | Key agreement without secret transmission |
| Encryption | AES-256-GCM | Authenticated encryption with AAD |
| KDF | HKDF-SHA256 | Key derivation |
| Nonce | Counter + prefix | Nonce reuse prevention |
| Integrity | SHA-256 | File integrity verification |
| Signaling | AES-256-GCM (pre-shared) | Session metadata encryption |
| Transport | TLS 1.2+ (WSS) | Transport layer encryption |

### Attack Mitigations

- **MITM** — mandatory security code verification
- **Replay** — counter-based nonces with unique prefix
- **Cross-session** — session code as AAD in AES-GCM
- **Eavesdropping** — E2E encryption; relay server sees only ciphertext
- **Server compromise** — server never has access to plaintext data

### Limitations

- Maximum **5 GB per session** (server-enforced limit)
- One file per session (use archives for multiple files)
- Both devices must have internet access
- Session codes are single-use
- macOS is not officially supported (run from source)

## Logs

Application logs are saved to:
```
%APPDATA%\SecureShare\secureshare.log
```

Use the built-in "Copy Log" or "Save Log" buttons for diagnostics.

## Author

**Artem Marchenko** — © 2026. MIT License.
