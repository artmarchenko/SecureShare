# Changelog

## Android 1.0.0 — 2026-10

First version of SecureShare for Android. Works with SecureShare 4.x on Windows and Linux (protocol v2) and with other phones.

### New
- Send and receive files up to 5 GB, end-to-end encrypted; the same session code and verification code as on the computer.
- Send from any app: **Share → SecureShare**.
- **Invitation links:** Share on the session code sends `https://secureshare-relay.duckdns.org/r#<code>` — on a phone with SecureShare it opens the app with the code filled in, elsewhere it shows the code and where to get the app. The code is after `#`, so it never reaches the server.
- Transfers continue with the screen off or the app in the background; progress and **Cancel** in the notification.
- Automatic reconnect and resume after a dropped connection; after an interrupted transfer, sending the same file again continues where it stopped.
- Received files go to **Download/SecureShare**; existing files are never overwritten.
- Ukrainian, English and German; light and dark theme; network diagnostics.
- Checks for new Android versions on GitHub.

## 4.0.0 — 2026-10

**Breaking:** 4.x clients cannot connect to 3.x clients. Both sides need 4.0 or newer.

### Security
- **Protocol v2.** A compromised relay server can no longer intercept transfers unnoticed:
  - the session code is never sent to the server — it only sees a room ID derived with scrypt;
  - commit-then-reveal key exchange: a relay substituting keys gets one blind guess (2⁻⁴⁰) instead of being able to search for matching verification codes;
  - verification code is now 8 base32 characters (40 bits, e.g. `K7PQ-2XMA`) bound to both public keys;
  - reconnect without re-verification uses a proof under the previous session key over the new keys (replaces a token the relay could replay);
  - every frame authenticates room, author and chunk number — no reordering, moving or reflecting frames.
- **Signed updates.** The auto-updater installs only releases whose `SHA256SUMS.txt` is signed with the author's Ed25519 key, and refuses updates without checksums (was: installed anyway).
- Received file names are sanitised on every OS (`\` and `/`, `:` for NTFS streams, reserved names like `CON`).
- Relay logs no longer contain IP addresses; container logs are size-limited.
- Rotated the relay admin key after it was found in an old commit.

### New
- German interface language; live language switch (UA / EN / DE).
- Existing files are never overwritten — the new one is saved as `name (1).ext`.
- Privacy switches in **Diagnostics**: anonymous crash reports (on by default) and transfer statistics (off by default).
- Hint when the other side never connects (likely still on 3.x).

### Fixed
- **Cancel** reacts immediately (was up to 2 minutes while waiting for the receiver), also during reconnect pauses.
- Window layout: footer and buttons are never clipped; the log area absorbs height changes.
- An unanswered verification dialog closes after 2 minutes and says why.
- Diagnostics: WebSocket check now works in the packaged app; internet check uses port 443.
- Update downloads no longer leave temporary folders behind.
- Server statistics survive a restart right after a month change.
- Linux build: translations are bundled again (the 3.4 Linux binary showed raw message keys).

### Under the hood
- Automated test suite (≈300 tests: unit, server, integration with a real relay, malicious-peer, GUI incl. full transfers through the window) on Windows and Linux; releases build only from a green suite.
- `--self-test` for packaged builds, UI screenshots on every change, regression guard for versions and translations.
- Transfer code restructured (shared reconnect/session logic, typed transfer states, GUI split into modules).

## 3.3.1 — 2026-02-21
Last release of protocol v1.
