/// Secrets derived from the session code (known only to the two users).
library;

import 'dart:convert';
import 'dart:io' show Platform;
import 'dart:isolate';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/services.dart' show MethodChannel;
import 'package:pointycastle/export.dart' as pc;

import 'constants.dart';

final _hmacSha256 = Hmac.sha256();

/// HKDF-SHA256 as in Python's `cryptography` (empty salt ≙ zero salt).
Future<List<int>> hkdf(List<int> ikm, List<int> info, {int length = 32, List<int>? salt}) async {
  final key = await Hkdf(hmac: _hmacSha256, outputLength: length)
      .deriveKey(secretKey: SecretKey(ikm), nonce: salt ?? const <int>[], info: info);
  return key.extractBytes();
}

String hex(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

List<int> unhex(String s) =>
    [for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)];

Uint8List _normalisedCode(String sessionCode) =>
    Uint8List.fromList(utf8.encode(sessionCode.trim().toLowerCase()));

/// scrypt(code) in pure Dart — slow on phones (~2 s on an emulator); used for
/// tests on the host and as a fallback.
Uint8List scryptMasterDart(String sessionCode) {
  final kdf = pc.Scrypt()
    ..init(pc.ScryptParameters(scryptN, scryptR, scryptP, 32, Uint8List.fromList(labelBytes('|code'))));
  return kdf.process(_normalisedCode(sessionCode));
}

const _native = MethodChannel('secureshare/native');

/// scrypt(code) without blocking the UI: BouncyCastle on Android (fast),
/// otherwise pure Dart in a background isolate.
Future<Uint8List> scryptMaster(String sessionCode) async {
  if (Platform.isAndroid) {
    try {
      final key = await _native.invokeMethod<Uint8List>('scrypt', {
        'password': _normalisedCode(sessionCode),
        'salt': Uint8List.fromList(labelBytes('|code')),
        'n': scryptN,
        'r': scryptR,
        'p': scryptP,
        'length': 32,
      });
      if (key != null && key.length == 32) return key;
    } catch (_) {
      // fall through to the Dart implementation
    }
  }
  return Isolate.run(() => scryptMasterDart(sessionCode));
}

class SessionSecrets {
  SessionSecrets._(this.roomId, this.signalingKey, this.master);

  /// Sent to the relay instead of the code.
  final String roomId;

  /// Encrypts key-exchange / verification messages.
  final List<int> signalingKey;

  /// Salt for the E2E data key.
  final List<int> master;

  static Future<SessionSecrets> fromMaster(List<int> master) async {
    final room = await hkdf(master, labelBytes('|room'), length: 16);
    final signaling = await hkdf(master, labelBytes('|signaling'));
    return SessionSecrets._(hex(room), signaling, master);
  }

  static Future<SessionSecrets> fromCode(String sessionCode) async =>
      fromMaster(await scryptMaster(sessionCode));
}
