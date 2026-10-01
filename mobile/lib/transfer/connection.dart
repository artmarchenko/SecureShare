/// WebSocket connection to the relay with sequential receive + timeouts.
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:async/async.dart';

class ConnectionClosed implements Exception {
  const ConnectionClosed();
  @override
  String toString() => 'connection closed';
}

class RelayConnection {
  RelayConnection._(this._ws) : _incoming = StreamQueue<dynamic>(_ws);

  final WebSocket _ws;
  final StreamQueue<dynamic> _incoming;

  /// Connects and registers [roomId] (the relay never sees the session code).
  static Future<RelayConnection> open(String url, String roomId,
      {Duration timeout = const Duration(seconds: 30)}) async {
    final ws = await WebSocket.connect(url).timeout(timeout);
    ws.pingInterval = const Duration(seconds: 30);
    ws.add(roomId);
    return RelayConnection._(ws);
  }

  bool get isOpen => _ws.closeCode == null;

  void sendBinary(List<int> frame) => _ws.add(frame is Uint8List ? frame : Uint8List.fromList(frame));

  /// Sends many frames with TCP backpressure: the [frames] stream is paused
  /// while the socket buffer is full (no unbounded buffering of a 5 GB file).
  Future<void> sendStream(Stream<List<int>> frames) => _ws.addStream(frames);

  /// Next binary message; throws [TimeoutException] or [ConnectionClosed].
  Future<Uint8List> receive(Duration timeout) async {
    while (true) {
      final bool hasNext;
      try {
        hasNext = await _incoming.hasNext.timeout(timeout);
      } on TimeoutException {
        rethrow;
      }
      if (!hasNext) throw const ConnectionClosed();
      final msg = await _incoming.next;
      if (msg is List<int>) return msg is Uint8List ? msg : Uint8List.fromList(msg);
      // text messages are not part of the protocol after the room ID; skip
    }
  }

  Future<void> close() async {
    try {
      await _ws.close().timeout(const Duration(seconds: 3));
    } catch (_) {}
    try {
      await _incoming.cancel(immediate: true);
    } catch (_) {}
  }
}
