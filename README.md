# SecureShare

**End-to-end encrypted file transfer between devices** — a standalone app for Windows, Linux and Android. No registration, no cloud storage, no network configuration.

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-4.0.0-green)

## What it is

SecureShare sends one file from one person to another over the internet. Both sides run the app; the sender gets a session code, tells it to the receiver, both compare a short verification code, and the file travels encrypted through a relay server that only ever sees ciphertext.

### Key Features

- **End-to-end encryption** — X25519 key exchange + AES-256-GCM
- **Relay that learns nothing** — it never receives the session code, the file, its name or its size in clear
- **MITM-resistant verification** — commit-then-reveal key exchange + 8-character code (40 bits) both users compare; a compromised relay gets one blind guess
- **Integrity** — every frame authenticated, whole-file SHA-256 check
- **Resume & auto-reconnect** — transfers survive network drops and app restarts (7 days)
- **Signed auto-update** — updates are installed only if their checksums carry the author's Ed25519 signature
- **Never overwrites** — a file with the same name is saved as `name (1).ext`
- **Languages** — Ukrainian, English, German
- **Diagnostics & privacy switches** — connectivity checks; crash reports (on by default) and transfer statistics (opt-in) can be toggled
- **Up to 5 GB per session**

## How to Use

**Sender**
1. Launch SecureShare, choose a file, click **Send**
2. Tell the receiver the session code (e.g. `a7f3-bc21`)
3. Compare the verification code (e.g. `K7PQ-2XMA`) with the receiver — by voice or in a messenger — and confirm

**Receiver**
1. Launch SecureShare, open **Receive**, enter the session code, choose a folder, click **Receive**
2. Compare the verification code and confirm; the file is saved when the transfer completes

> Both sides need SecureShare **4.0 or newer** — 4.x cannot connect to 3.x.

### Android

[Download SecureShare.apk](https://secureshare-relay.duckdns.org/download/SecureShare.apk) (Android 7.0+), open it on the phone and allow the installation when asked. Other builds (universal, 32-bit, x86_64) are on the [releases page](https://github.com/artmarchenko/SecureShare/releases) under `android-v*`.

- Works with SecureShare 4.x on the computer in both directions, and phone to phone.
- Send from any app via **Share → SecureShare**; received files go to **Download/SecureShare**.
- **Invitation links** — sharing the session code sends `https://secureshare-relay.duckdns.org/r#<code>`: it opens the app with the code filled in, or shows the code in a browser. The code is in the `#` part, which browsers never send to the server.
- Transfers keep running with the screen off; progress and Cancel in the notification.
- APK signing certificate SHA-256: `64:33:7E:8C:F0:78:98:45:A3:F4:93:C9:57:E3:0E:D6:22:72:D9:C0:E3:4D:AD:70:36:00:4B:DA:2F:85:71:EC` — check with `apksigner verify --print-certs SecureShare.apk`.

Source: [`mobile/`](mobile/) (Flutter).

## How It Works

```
Sender                              Relay (sees only room ID + ciphertext)          Receiver
  │── room ID = HKDF(scrypt(code)) ─────►│◄─────────────────────── room ID ──────────│
  │── commit = H(sender key) ───────────►│──────────────────────────────────────────►│
  │◄─────────────────────────────────────│◄─────────────────────── receiver key ─────│
  │── reveal sender key ────────────────►│──────────────────────────────────────────►│  checks commitment
  │   both derive the AES key and show the same 8-character code → users compare    │
  │══ AES-256-GCM chunks (authenticated chunk numbers) ═════════════════════════════►│
  │◄──────────────────────────────────────────────────────── SHA-256 verified ───────│
```

| Component | Technology |
|-----------|------------|
| Client | Python + CustomTkinter |
| Relay server | Python + websockets (Docker) |
| TLS | Caddy + Let's Encrypt |
| Hosting | Oracle Cloud (Always Free) |

Details: [DEVELOPER.md](DEVELOPER.md) (protocol, threat model, CI/CD) · [USER_GUIDE.md](USER_GUIDE.md) (Ukrainian user guide).

## Security

| What | How |
|------|-----|
| Key exchange | X25519, fresh keys per connection |
| Encryption | AES-256-GCM; AAD binds room, author role, frame type and chunk number |
| MITM | commit-then-reveal + 40-bit verification code bound to both public keys |
| Session code | never sent; the relay gets an scrypt-derived room ID |
| Reconnect | proof under the previous session key over the new keys (no bearer token) |
| Updates | Ed25519-signed `SHA256SUMS.txt`, fail-closed |

**What the relay cannot do:** read or change your file, learn its name, learn the session code, or impersonate the other side without the users noticing a code mismatch.
**What it can do:** see that two IP addresses exchanged some amount of data, or refuse to relay.
**What you must do:** actually compare the verification code.

### Limitations

- Maximum 5 GB per session; one file per session (use an archive for several)
- Both devices need internet access at the same time
- Windows and Linux builds; macOS: run from source

## Development

```bash
pip install -r requirements-dev.txt   # app + server + test dependencies
python main.py                        # run from source
python -m pytest                      # full test suite (unit, server, integration, adversarial, UI)
python build.py                       # dist/SecureShare.exe (Windows) or dist/SecureShare (Linux)
```

Every push runs the tests on Windows and Linux; releases are built only from a green suite and are signed. See [DEVELOPER.md](DEVELOPER.md).

## Project Structure

```
app/            client: crypto_utils, ws_relay, gui, ui/, diagnostics, updater, telemetry, i18n, lang/
server/         relay_server, analytics, Docker/Caddy config, landing page (www/)
tests/          pytest suites: unit, server, integration, adversarial, ui
scripts/        regression guard, release signing, UI screenshots
main.py         entry point (--self-test for packaged builds)
build.py        PyInstaller build (Windows + Linux)
```

## Logs

`%APPDATA%\SecureShare\secureshare.log` on Windows. The **Copy log** / **Save log** buttons help with support requests.

## Author

**Artem Marchenko** — © 2026. MIT License.
