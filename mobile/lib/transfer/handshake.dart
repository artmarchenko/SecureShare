/// Key exchange (commit-then-reveal) and verification — port of
/// `_do_key_exchange` / `_do_verification` in app/ws_relay.py.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';

import '../protocol/constants.dart';
import '../protocol/crypto_session.dart';
import '../protocol/secrets.dart';
import 'connection.dart';

const appVersion = '1.0.0';

typedef Emit = void Function(String key, [Map<String, Object?> args]);

class SignalingError implements Exception {
  SignalingError(this.key, [this.args = const {}]);
  final String key;
  final Map<String, Object?> args;
  @override
  String toString() => 'SignalingError($key)';
}

class KeyExchangeResult {
  KeyExchangeResult(this.crypto, {required this.fatal, required this.proven});
  final CryptoSession? crypto;

  /// Failure that must not be retried (incompatible version, commitment mismatch).
  final bool fatal;

  /// The peer proved it holds the previous session's key → skip the dialog.
  final bool proven;
}

class Signaling {
  Signaling(this.conn, this.key);
  final RelayConnection conn;
  final List<int> key;

  Future<void> send(Map<String, Object?> msg) async =>
      conn.sendBinary([frameSignaling, ...await signalingEncrypt(key, utf8.encode(jsonEncode(msg)))]);

  Future<Map<String, dynamic>> receive(String expectedType, Duration timeout) async {
    final List<int> raw;
    try {
      raw = await conn.receive(timeout);
    } catch (e) {
      throw SignalingError('relay_key_exchange_error', {'error': e.toString()});
    }
    if (raw.length < 2 || raw[0] != frameSignaling) throw SignalingError('relay_key_format_error');
    final Object? msg;
    try {
      msg = jsonDecode(utf8.decode(await signalingDecrypt(key, raw.sublist(1))));
    } catch (_) {
      throw SignalingError('relay_key_decrypt_error');
    }
    if (msg is! Map<String, dynamic>) throw SignalingError('relay_key_message_error');
    if (msg.containsKey('protocol_version')) _checkPeerVersion(msg);
    if (msg['type'] != expectedType) throw SignalingError('relay_key_message_error');
    return msg;
  }
}

void _checkPeerVersion(Map<String, dynamic> msg) {
  final peer = msg['protocol_version'];
  if (peer is! int || peer < minProtocolVersion) {
    throw SignalingError('relay_incompatible', {'peer_proto': peer, 'min_proto': minProtocolVersion});
  }
  if (peer > protocolVersion) {
    throw SignalingError('relay_peer_newer', {'peer_app': msg['app_version'] ?? 'unknown'});
  }
}

List<int> _unb64(Object? value, int length) {
  if (value is! String) throw SignalingError('relay_key_message_error');
  final List<int> data;
  try {
    data = base64.decode(value);
  } catch (_) {
    throw SignalingError('relay_key_message_error');
  }
  if (data.length != length) throw SignalingError('relay_key_message_error');
  return data;
}

final _random = Random.secure();

Future<KeyExchangeResult> keyExchange(
  RelayConnection conn,
  SessionSecrets secrets,
  String role,
  Emit emit, {
  CryptoSession? previous,
  Duration peerWait = const Duration(minutes: 5),
  Duration stepTimeout = const Duration(minutes: 2),
}) async {
  final crypto = await CryptoSession.create(secrets, role);
  final sig = Signaling(conn, secrets.signalingKey);
  final mine = crypto.publicKey;
  final hello = {'protocol_version': protocolVersion, 'app_version': appVersion};
  Map<String, dynamic>? first;
  try {
    late List<int> peerPub;
    if (role == roleSender) {
      final opening = List<int>.generate(32, (_) => _random.nextInt(256));
      final commit = await commitment(mine, opening);
      await sig.send({'type': 'commit', 'commit': base64.encode(commit), ...hello});
      emit('relay_key_exchange');
      first = await sig.receive('pub_key', peerWait);
      peerPub = _unb64(first['key'], 32);
      await sig.send({'type': 'reveal', 'key': base64.encode(mine), 'opening': base64.encode(opening)});
    } else {
      emit('relay_key_exchange');
      first = await sig.receive('commit', peerWait);
      final commit = _unb64(first['commit'], 32);
      await sig.send({'type': 'pub_key', 'key': base64.encode(mine), ...hello});
      final reveal = await sig.receive('reveal', stepTimeout);
      peerPub = _unb64(reveal['key'], 32);
      if (!await checkCommitment(commit, peerPub, _unb64(reveal['opening'], 32))) {
        emit('relay_commit_mismatch'); // keys swapped after the commitment: an attack
        return KeyExchangeResult(null, fatal: true, proven: false);
      }
    }
    emit('relay_protocol_info', {
      'our_proto': protocolVersion,
      'peer_proto': first['protocol_version'],
      'our_app': appVersion,
      'peer_app': first['app_version'] ?? 'unknown',
    });
    try {
      await crypto.deriveSharedKey(peerPub);
    } catch (_) {
      throw SignalingError('relay_key_message_error');
    }
    final proof = previous == null ? null : await crypto.reconnectProof(previous);
    await sig.send({'type': 'session_proof', 'mac': proof == null ? null : base64.encode(proof)});
    final peerMac = (await sig.receive('session_proof', stepTimeout))['mac'];
    final proven = previous != null &&
        peerMac != null &&
        await crypto.checkReconnectProof(previous, _unb64(peerMac, 32));
    return KeyExchangeResult(crypto, fatal: false, proven: proven);
  } on SignalingError catch (e) {
    emit(e.key, e.args);
    if (first == null && e.key == 'relay_key_exchange_error') {
      emit('relay_peer_version_hint'); // v3.x peers use a different room
    }
    return KeyExchangeResult(null,
        fatal: e.key == 'relay_incompatible' || e.key == 'relay_peer_newer', proven: false);
  } catch (e) {
    emit('relay_key_exchange_error', {'error': e.toString()});
    return KeyExchangeResult(null, fatal: false, proven: false);
  }
}

/// Both users confirm the code (or it is skipped on a proven reconnect).
Future<bool> verify(
  RelayConnection conn,
  CryptoSession crypto,
  Future<bool> Function(String code) askUser,
  Emit emit, {
  required bool autoVerify,
  Duration timeout = const Duration(minutes: 2),
}) async {
  final sig = Signaling(conn, crypto.secrets.signalingKey);
  Future<Map<String, dynamic>?> peerAnswer(String errorKey) async {
    try {
      final raw = await conn.receive(timeout);
      if (raw.length < 2 || raw[0] != frameSignaling) {
        emit('relay_verify_format_error');
        return null;
      }
      final msg = jsonDecode(utf8.decode(await signalingDecrypt(sig.key, raw.sublist(1))));
      return msg is Map<String, dynamic> ? msg : null;
    } on FormatException {
      emit('relay_verify_decrypt_error');
      return null;
    } catch (e) {
      emit(errorKey, {'error': e.toString()});
      return null;
    }
  }

  if (autoVerify) {
    emit('relay_auto_verify');
    await sig.send({'type': 'verified'});
    final msg = await peerAnswer('relay_auto_verify_error');
    if (msg?['type'] == 'verified') {
      emit('relay_auto_verify_ok');
      return true;
    }
    return false;
  }

  final code = await crypto.verificationCode();
  emit('relay_verify_code', {'code': code});
  if (!await askUser(code)) {
    try {
      await sig.send({'type': 'verify_reject'});
    } catch (_) {}
    emit('relay_verify_rejected');
    return false;
  }
  await sig.send({'type': 'verified'});
  emit('relay_verify_confirmed');
  final msg = await peerAnswer('relay_verify_error');
  if (msg == null) return false;
  if (msg['type'] == 'verify_reject') {
    emit('relay_peer_rejected');
    return false;
  }
  if (msg['type'] != 'verified') {
    emit('relay_verify_msg_error');
    return false;
  }
  emit('relay_both_verified');
  return true;
}
