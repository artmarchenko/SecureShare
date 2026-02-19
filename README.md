# SecureShare

**Secure end-to-end encrypted file sharing** — a standalone .exe for transferring files securely between two computers over the internet.

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-proprietary-red)
![Version](https://img.shields.io/badge/version-3.0.0-green)

## What is it

SecureShare is a desktop application with a graphical interface for one-time secure file transfers between two users. No registration, no network configuration, no white IP addresses required.

### Key Features

- **End-to-End Encryption** — X25519 (ECDH) + AES-256-GCM
- **VPS Relay** — dedicated relay server with automatic TLS (Let's Encrypt)
- **MITM Verification** — visual security code comparison
- **SHA-256 Integrity** — hash verification after transfer
- **Built-in Diagnostics** — connectivity and server health checks
- **Single .exe file** — no installation, no dependencies
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
- Windows 10/11

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run from Source

```bash
python main.py
```

### Build .exe

```bash
pyinstaller SecureShare.spec
```

Result: `dist/SecureShare.exe`

## Project Structure

```
fileshare/
├── app/
│   ├── config.py          # Configuration (VPS URL, limits, version)
│   ├── crypto_utils.py    # X25519, AES-256-GCM, HKDF, signaling crypto
│   ├── gui.py             # CustomTkinter GUI + transfer orchestration
│   └── ws_relay.py        # VPS WebSocket relay sender/receiver
├── server/
│   ├── relay_server.py    # VPS relay server (Python + websockets)
│   ├── Dockerfile         # Docker image for relay server
│   ├── docker-compose.yml # Docker Compose (relay + Caddy)
│   ├── Caddyfile          # Caddy reverse proxy + auto-TLS
│   ├── test_relay.py      # Server test suite
│   └── DEPLOY.md          # Deployment instructions (Oracle Cloud)
├── main.py                # Entry point
├── requirements.txt       # Python dependencies
├── SecureShare.spec        # PyInstaller build spec
└── version_info.txt       # .exe metadata (version, publisher)
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

## Logs

Application logs are saved to:
```
%APPDATA%\SecureShare\secureshare.log
```

Use the built-in "Copy Log" or "Save Log" buttons for diagnostics.

## Author

**Artem Marchenko** — (c) 2026. All rights reserved.
