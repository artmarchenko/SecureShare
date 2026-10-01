# SecureShare for Android (Flutter)

Work in progress — see `MOBILE_PLAN.md` in the repository root.

- `lib/protocol/` — protocol v2 core (pure Dart + native scrypt on Android): session secrets from the code, X25519 key exchange with commit-then-reveal, verification code, reconnect proofs, AES-GCM frames with AAD, chunk compression, file-name sanitising.
- `test/protocol_vectors_test.dart` — reproduces `../tests/vectors/protocol_v2.json` (generated from the Python desktop app) byte for byte.
- `android/app/src/main/kotlin/.../MainActivity.kt` — `secureshare/native` channel: scrypt via BouncyCastle (≈2× faster than pure Dart).
- `lib/bench_main.dart` — developer benchmark: `flutter run --release -t lib/bench_main.dart`.

```bash
flutter test      # protocol vectors
flutter analyze
```
