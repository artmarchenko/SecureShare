/// One E2E-encrypted session (port of `CryptoSession` in app/crypto_utils.py).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'constants.dart';
import 'secrets.dart';

final _x25519 = X25519();
final _aesGcm = AesGcm.with256bits();
final _hmac = Hmac.sha256();
final _sha256 = Sha256();

/// Commit-then-reveal: SHA256(label|commit ‖ public key ‖ opening).
Future<List<int>> commitment(List<int> publicKey, List<int> opening) async =>
    (await _sha256.hash([...labelBytes('|commit'), ...publicKey, ...opening])).bytes;

Future<bool> checkCommitment(List<int> commit, List<int> publicKey, List<int> opening) async =>
    constantTimeEquals(await commitment(publicKey, opening), commit);

bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

const _base32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/// RFC 4648 base32 of exactly 5 bytes → 8 characters (no padding needed).
String base32Of5(List<int> b) {
  var bits = 0;
  for (final x in b) {
    bits = (bits << 8) | x;
  }
  return [for (var i = 7; i >= 0; i--) _base32[(bits >> (i * 5)) & 31]].join();
}

class CryptoSession {
  CryptoSession._(this.secrets, this.role, this._keyPair, this._publicKey);

  final SessionSecrets secrets;
  final String role;
  final SimpleKeyPair _keyPair;
  final List<int> _publicKey;

  List<int>? _sharedKey;
  SecretKey? _aesKey;
  int _sendCounter = 0;
  List<int> transcript = const [];

  /// [privateKey] (raw 32 bytes) only for deterministic test vectors.
  static Future<CryptoSession> create(SessionSecrets secrets, String role, {List<int>? privateKey}) async {
    if (role != roleSender && role != roleReceiver) {
      throw ArgumentError('unknown role $role');
    }
    final keyPair = privateKey == null
        ? await _x25519.newKeyPair()
        : await _x25519.newKeyPairFromSeed(privateKey);
    final pub = (await keyPair.extractPublicKey()).bytes;
    return CryptoSession._(secrets, role, keyPair, pub);
  }

  List<int> get publicKey => _publicKey;
  String get peerRole => role == roleSender ? roleReceiver : roleSender;
  int get sendCounter => _sendCounter;
  int get _noncePrefix => role == roleSender ? 0 : 1;

  /// Data key = HKDF(DH secret, salt = master, info = label|data-key| ‖ transcript).
  Future<void> deriveSharedKey(List<int> peerPublicKey) async {
    final raw = await _x25519.sharedSecretKey(
      keyPair: _keyPair,
      remotePublicKey: SimplePublicKey(peerPublicKey, type: KeyPairType.x25519),
    );
    transcript = role == roleSender ? [..._publicKey, ...peerPublicKey] : [...peerPublicKey, ..._publicKey];
    _sharedKey = await hkdf(await raw.extractBytes(), [...labelBytes('|data-key|'), ...transcript],
        salt: secrets.master);
    _aesKey = SecretKey(_sharedKey!);
  }

  List<int> get _key {
    final k = _sharedKey;
    if (k == null) throw StateError('Call deriveSharedKey first');
    return k;
  }

  /// Exposed for tests only.
  List<int> get sharedKeyForTests => _key;

  Future<List<int>> mac(List<int> data) async =>
      (await _hmac.calculateMac(data, secretKey: SecretKey(_key))).bytes;

  /// 8-character base32 code both users compare, e.g. "K7PQ-2XMA".
  Future<String> verificationCode() async {
    final sas = await hkdf(_key, [...labelBytes('|sas|'), ...transcript], length: sasBytes);
    final text = base32Of5(sas);
    return '${text.substring(0, 4)}-${text.substring(4)}';
  }

  Future<List<int>> reconnectProof(CryptoSession previous) =>
      previous.mac([...labelBytes('|reconnect|'), ...utf8.encode(role), 0x7c, ...transcript]);

  Future<bool> checkReconnectProof(CryptoSession previous, List<int> proof) async => constantTimeEquals(
      await previous.mac([...labelBytes('|reconnect|'), ...utf8.encode(peerRole), 0x7c, ...transcript]), proof);

  List<int> _aad(String author, List<int> aad) =>
      [...labelBytes('|'), ...ascii.encode(secrets.roomId), 0x7c, ...ascii.encode(author), 0x7c, ...aad];

  /// 12-byte nonce ‖ ciphertext ‖ 16-byte tag. AAD binds room, author role and [aad].
  Future<Uint8List> encrypt(List<int> plaintext, List<int> aad) async {
    final key = _aesKey;
    if (key == null) throw StateError('Call deriveSharedKey first');
    final nonce = ByteData(12)
      ..setUint32(0, _noncePrefix)
      ..setUint64(4, _sendCounter);
    _sendCounter++;
    final box = await _aesGcm.encrypt(plaintext,
        secretKey: key, nonce: nonce.buffer.asUint8List(), aad: _aad(role, aad));
    return Uint8List.fromList([...box.nonce, ...box.cipherText, ...box.mac.bytes]);
  }

  /// Decrypt a frame the *peer* produced with encrypt(..., [aad]); throws on tampering.
  Future<List<int>> decrypt(List<int> data, List<int> aad) async {
    final key = _aesKey;
    if (key == null) throw StateError('Call deriveSharedKey first');
    if (data.length < 28) throw const FormatException('frame too short');
    final box = SecretBox(data.sublist(12, data.length - 16),
        nonce: data.sublist(0, 12), mac: Mac(data.sublist(data.length - 16)));
    return _aesGcm.decrypt(box, secretKey: key, aad: _aad(peerRole, aad));
  }
}

/// Signaling messages: AES-256-GCM with the code-derived key, random nonce.
Future<Uint8List> signalingEncrypt(List<int> key, List<int> plaintext) async {
  final box = await _aesGcm.encrypt(plaintext,
      secretKey: SecretKey(key), nonce: _aesGcm.newNonce(), aad: labelBytes('|signaling'));
  return Uint8List.fromList([...box.nonce, ...box.cipherText, ...box.mac.bytes]);
}

Future<List<int>> signalingDecrypt(List<int> key, List<int> data) {
  final box = SecretBox(data.sublist(12, data.length - 16),
      nonce: data.sublist(0, 12), mac: Mac(data.sublist(data.length - 16)));
  return _aesGcm.decrypt(box, secretKey: SecretKey(key), aad: labelBytes('|signaling'));
}
