/// SecureShare protocol v2 — constants shared with the desktop app.
///
/// Every value here must match `app/crypto_utils.py` / `app/ws_relay.py`;
/// `test/protocol_vectors_test.dart` checks the whole protocol against
/// `tests/vectors/protocol_v2.json`.
library;

import 'dart:convert';

const int protocolVersion = 2;
const int minProtocolVersion = 2;

/// Domain-separation label (`LABEL` in Python).
const String label = 'secureshare-p2';

List<int> labelBytes(String suffix) => utf8.encode('$label$suffix');

// scrypt cost for the session code — must not change (interoperability).
const int scryptN = 32768; // 2^15
const int scryptR = 8;
const int scryptP = 1;

const int sasBytes = 5; // 40-bit verification code → 8 base32 chars

const String roleSender = 'sender';
const String roleReceiver = 'receiver';

// Wire frame types (first byte of every WebSocket message).
const int frameSignaling = 0x53; // 'S'
const int frameControl = 0x43; // 'C'
const int frameData = 0x44; // 'D'

const int chunkSize = 512 * 1024;
const int maxFileSize = 5 * 1024 * 1024 * 1024;

const int compressedFlag = 0x01;
const int rawFlag = 0x00;
