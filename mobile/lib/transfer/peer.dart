/// Behaviour shared by sender and receiver — port of `_RelayPeer` in
/// app/ws_relay.py: reconnect loop, session setup, cancel, status reporting.
library;

import 'dart:async';
import 'dart:io';
import 'dart:math';

import '../protocol/crypto_session.dart';
import '../protocol/secrets.dart';
import 'connection.dart';
import 'handshake.dart';
import 'status.dart';

enum Attempt { success, fatal, retry }

class TransferOptions {
  const TransferOptions({
    this.relayUrl = 'wss://secureshare-relay.duckdns.org',
    this.maxRetries = 5,
    this.baseDelay = const Duration(seconds: 5),
    this.maxDelay = const Duration(seconds: 60),
    this.peerWait = const Duration(minutes: 5),
    this.stepTimeout = const Duration(minutes: 2),
  });

  final String relayUrl;
  final int maxRetries;
  final Duration baseDelay, maxDelay, peerWait, stepTimeout;
}

abstract class RelayPeer {
  RelayPeer(this.code, this.options, {this.onStatus, this.onState, this.onProgress, required this.onVerify});

  final String code;
  final TransferOptions options;
  final StatusCallback? onStatus;
  final StateCallback? onState;
  final ProgressCallback? onProgress;
  final VerifyCallback onVerify;

  String get role; // roleSender / roleReceiver
  String get waitingKey; // status shown while waiting for the peer

  bool _cancelled = false;
  final _cancelSignal = Completer<void>();
  RelayConnection? conn;
  CryptoSession? crypto;
  SessionSecrets? _secrets;
  CryptoSession? _previous; // last verified session (reconnect proof)

  bool get cancelled => _cancelled;

  void cancel() {
    _cancelled = true;
    if (!_cancelSignal.isCompleted) _cancelSignal.complete();
    unawaited(conn?.close());
  }

  void emit(String key, [Map<String, Object?> args = const {}]) {
    onStatus?.call(key, args);
    final state = stateForMessage[key];
    if (state != null) onState?.call(state);
  }

  /// Runs [attempt] until success, a fatal failure or the retry limit.
  Future<T> runWithReconnect<T>(Future<(Attempt, T)> Function(bool isReconnect) attempt, T failure) async {
    for (var n = 0; n <= options.maxRetries; n++) {
      if (_cancelled) return failure;
      if (n > 0 && !await _backoff(n)) return failure;
      beforeAttempt();
      try {
        final (outcome, value) = await attempt(n > 0);
        if (outcome == Attempt.success) return value;
        if (outcome == Attempt.fatal || _cancelled) return failure;
        emit('relay_connection_lost');
      } catch (e) {
        emit('transfer_error_generic', {'error': e.toString()});
      } finally {
        await conn?.close();
        conn = null;
      }
    }
    emit('relay_retries_exhausted');
    return failure;
  }

  Future<bool> _backoff(int n) async {
    final ms = min(options.baseDelay.inMilliseconds * pow(2, n - 1), options.maxDelay.inMilliseconds).toInt();
    emit('relay_reconnecting', {'delay': (ms / 1000).toStringAsFixed(0), 'attempt': n, 'max': options.maxRetries});
    await Future.any([Future<void>.delayed(Duration(milliseconds: ms)), _cancelSignal.future]);
    return !_cancelled;
  }

  void beforeAttempt() {}

  /// Connect → key exchange → verification. Null on success, otherwise how
  /// the attempt should end.
  Future<Attempt?> openSession(bool isReconnect) async {
    emit(isReconnect ? 'relay_reconnecting_to' : 'relay_connecting_to');
    _secrets ??= await SessionSecrets.fromCode(code); // scrypt once per transfer
    try {
      conn = await RelayConnection.open(options.relayUrl, _secrets!.roomId);
    } catch (e) {
      emit('relay_connect_error', {'error': e.toString()});
      final dns = e is SocketException && e.osError?.errorCode != null && '$e'.contains('lookup');
      return (isReconnect || dns) ? Attempt.retry : Attempt.fatal;
    }
    emit(waitingKey);
    final kx = await keyExchange(conn!, _secrets!, role, (k, [a = const {}]) => emit(k, a),
        previous: _previous, peerWait: options.peerWait, stepTimeout: options.stepTimeout);
    if (kx.crypto == null) return (kx.fatal || !isReconnect) ? Attempt.fatal : Attempt.retry;
    crypto = kx.crypto;
    final ok = await verify(conn!, crypto!, onVerify, (k, [a = const {}]) => emit(k, a),
        autoVerify: kx.proven, timeout: options.stepTimeout);
    if (!ok) return Attempt.fatal;
    _previous = crypto;
    return null;
  }
}
