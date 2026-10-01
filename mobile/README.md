# SecureShare for Android (Flutter)

Send and receive files end-to-end encrypted, compatible with SecureShare 4.x on the desktop (protocol v2). Plan and status: `MOBILE_PLAN.md` in the repository root.

## Layout

- `lib/protocol/` — protocol v2 core (pure Dart + native scrypt on Android): session secrets from the code, X25519 key exchange with commit-then-reveal, verification code, reconnect proofs, AES-GCM frames with AAD, chunk compression, file-name sanitising.
- `lib/transfer/` — transfer engine, a port of `app/ws_relay.py`: handshake, verification, auto-reconnect, resume, retransmit, SHA-256 check, no-overwrite naming. Emits the desktop's status keys.
- `lib/app/` — app logic without widgets: `controller.dart` (one transfer at a time, notification updates), `device.dart` (what the app needs from Android, behind an interface), `i18n.dart`, `settings.dart`, `diagnostics.dart`.
- `lib/ui/` — screens: Send / Receive tabs, the transfer view (session code, verification, progress, result, log), help, diagnostics, settings.
- `android/.../kotlin/` — `SecureShareApp` (the Flutter engine lives with the process, so a transfer survives the activity being closed), `NativeBridge` (file picker and share intent, positional reads + SHA-256 of picked files, `Download/SecureShare`, permissions, scrypt), `TransferService` (foreground service with progress and Cancel, wake/Wi-Fi locks).
- `assets/lang/desktop/` — an exact copy of `../app/lang/*.json` (statuses, verification, help); `assets/lang/*.json` — texts of the mobile screens (`m_*`). `test/i18n_test.dart` fails if the copy is stale or a key is missing.

## Tests

```bash
flutter analyze
flutter test                                      # everything below except the emulator run
flutter test --exclude-tags interop,screenshots   # fast: protocol vectors, screens, layout, translations
flutter test --tags screenshots                   # every screen × uk/en/de × light/dark → build/screenshots/
python ../scripts/android_e2e.py                  # the app on an emulator ↔ local relay ↔ desktop client
```

- `test/ui/` — widget tests with a fake device and a scripted engine (send/receive flows, verification, cancel, notification Cancel, shared files, language switch), and a layout test: every screen in every language on a 320 dp screen and with 130–200 % system font must not overflow.
- `test/interop_test.dart` — the Dart engine against the repo's relay and `python -m app.cli` (both directions, network drop, cancel + resume, 64 MiB); `test/memory_probe_test.dart` — 256 MiB with flat memory.
- `integration_test/app_e2e_test.dart` — driven by `scripts/android_e2e.py`: PC → phone with the app sent to the background mid-transfer, phone → PC with the screen turned off.

## Running against a local relay

```bash
python scripts/local_relay.py --port 18765                 # from the repository root
flutter run --dart-define=RELAY_URL=ws://10.0.2.2:18765    # 10.0.2.2 = the host, seen from the emulator
python -m app.cli --relay ws://127.0.0.1:18765 send FILE   # the PC side
```

`lib/bench_main.dart` — developer benchmark: `flutter run --release -t lib/bench_main.dart`.
