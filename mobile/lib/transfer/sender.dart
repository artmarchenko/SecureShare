/// Sending a file â€” port of `VPSRelaySender` in app/ws_relay.py.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../protocol/constants.dart';
import '../protocol/frames.dart';
import 'peer.dart';
import 'storage.dart';

class TransferSender extends RelayPeer {
  TransferSender(super.code, this.source, super.options,
      {super.onStatus, super.onState, super.onProgress, required super.onVerify});

  final FileSource source;

  @override
  String get role => roleSender;
  @override
  String get waitingKey => 'relay_waiting_receiver';

  late int _size;
  late String _sha256;
  late String _transferId;
  final _controlQueue = <Map<String, dynamic>>[];
  Completer<Map<String, dynamic>?>? _controlWaiter;
  bool _lost = false;

  /// True on success (receiver verified the SHA-256), false otherwise.
  Future<bool> send() async {
    try {
      _size = await source.length();
      emit('relay_computing_hash', {'filename': source.name});
      _sha256 = await source.sha256Hex();
      _transferId = await transferId(source.name, _size, _sha256);
    } catch (e) {
      emit('relay_file_read_error', {'error': e.toString()});
      return false;
    }
    try {
      return await runWithReconnect(_attempt, false);
    } finally {
      await source.close();
    }
  }

  @override
  void cancel() {
    super.cancel();
    _deliver(null); // wake a pending _waitControl immediately
  }

  @override
  void beforeAttempt() {
    _lost = false;
    _controlQueue.clear();
    _controlWaiter = null;
  }

  void _deliver(Map<String, dynamic>? msg) {
    final w = _controlWaiter;
    if (w != null && !w.isCompleted) {
      _controlWaiter = null;
      w.complete(msg);
    } else if (msg != null) {
      _controlQueue.add(msg);
    }
  }

  Future<(Attempt, bool)> _attempt(bool isReconnect) async {
    final failed = await openSession(isReconnect);
    if (failed != null) return (failed, false);
    unawaited(_readControlFrames());
    final r = await _transfer();
    return r == true ? (Attempt.success, true) : (r == null ? (Attempt.retry, false) : (Attempt.fatal, false));
  }

  /// Background: decode control frames from the receiver into [_control].
  Future<void> _readControlFrames() async {
    final c = conn!;
    try {
      while (true) {
        final raw = await c.receive(const Duration(days: 1));
        if (raw.isNotEmpty && raw[0] == frameControl) {
          try {
            final msg = jsonDecode(utf8.decode(await crypto!.decrypt(raw.sublist(1), utf8.encode('C'))));
            if (msg is Map<String, dynamic>) _deliver(msg);
          } catch (_) {}
        }
      }
    } catch (_) {
      if (identical(c, conn)) {
        _lost = true;
        _deliver(null);
      }
    }
  }

  /// Next control message, or null on timeout / cancel / lost connection.
  Future<Map<String, dynamic>?> _waitControl(Duration timeout) async {
    if (_controlQueue.isNotEmpty) return _controlQueue.removeAt(0);
    if (_lost || cancelled) return null;
    final waiter = _controlWaiter = Completer<Map<String, dynamic>?>();
    try {
      return await waiter.future.timeout(timeout);
    } on TimeoutException {
      if (identical(_controlWaiter, waiter)) _controlWaiter = null;
      return null;
    }
  }

  Future<void> _sendControl(Map<String, Object?> msg) async {
    try {
      conn!.sendBinary([frameControl, ...await crypto!.encrypt(utf8.encode(jsonEncode(msg)), utf8.encode('C'))]);
    } catch (_) {
      _lost = true;
    }
  }

  Stream<List<int>> _frames(Iterable<int> seqs, void Function(int bytes) onChunk) async* {
    for (final seq in seqs) {
      if (cancelled || _lost) return;
      final offset = seq * chunkSize;
      final chunk = await source.read(offset, chunkSize);
      if (chunk.isEmpty) return;
      final seqBytes = (ByteData(4)..setUint32(0, seq)).buffer.asUint8List();
      final body = await crypto!.encrypt(compressChunk(chunk), [...utf8.encode('D'), ...seqBytes]);
      yield Uint8List.fromList([frameData, ...seqBytes, ...body]);
      onChunk(chunk.length);
    }
  }

  /// true = done, false = permanent failure, null = connection lost (retry).
  Future<bool?> _transfer() async {
    final totalChunks = (_size + chunkSize - 1) ~/ chunkSize;
    await _sendControl({
      'type': 'relay_meta', 'name': source.name, 'size': _size, 'sha256': _sha256,
      'chunk_size': chunkSize, 'total_chunks': totalChunks, 'transfer_id': _transferId,
    });
    emit('relay_waiting_meta_ack');
    final ack = await _waitControl(const Duration(minutes: 2));
    if (ack == null) {
      if (cancelled) return false;
      if (!_lost) emit('relay_meta_timeout');
      return null;
    }
    if (ack['type'] != 'relay_meta_ack') {
      emit('relay_meta_unexpected');
      return null;
    }

    final skip = <int>{};
    var resumeBytes = 0;
    if (ack['resume'] == true) {
      skip.addAll((ack['received_chunks'] as List? ?? const []).whereType<int>());
      resumeBytes = skip.length * chunkSize;
      if (skip.contains(totalChunks - 1)) {
        resumeBytes = resumeBytes - chunkSize + (_size - (totalChunks - 1) * chunkSize);
      }
      resumeBytes = resumeBytes.clamp(0, _size).toInt();
      emit('relay_resume_info', {
        'received': skip.length, 'total': totalChunks, 'mb': (resumeBytes / 1048576).toStringAsFixed(1),
      });
    }
    emit(skip.isEmpty ? 'relay_sending' : 'relay_sending_resume',
        {'filename': source.name, 'size': _size, 'chunks': totalChunks - skip.length});

    final sw = Stopwatch()..start();
    var sent = resumeBytes;
    var lastReport = Duration.zero;
    void progress(int bytes) {
      sent += bytes;
      if (sw.elapsed - lastReport >= const Duration(milliseconds: 300)) {
        lastReport = sw.elapsed;
        onProgress?.call(sent, _size, (sent - resumeBytes) / (sw.elapsedMicroseconds / 1e6));
      }
    }

    if (resumeBytes > 0) onProgress?.call(sent, _size, 0);
    try {
      await conn!.sendStream(_frames([for (var i = 0; i < totalChunks; i++) if (!skip.contains(i)) i], progress));
    } catch (_) {
      _lost = true;
    }
    if (cancelled) return false;
    if (_lost) return null;
    onProgress?.call(sent, _size, (sent - resumeBytes) / (sw.elapsedMicroseconds / 1e6 + 1e-9));

    final done = {'type': 'relay_done', 'sha256': _sha256, 'total_chunks': totalChunks};
    await _sendControl(done);
    emit('relay_waiting_integrity');
    var rounds = 0;
    final deadline = DateTime.now().add(const Duration(minutes: 10));
    while (DateTime.now().isBefore(deadline) && !cancelled) {
      final msg = await _waitControl(const Duration(seconds: 10));
      if (msg == null) {
        if (cancelled) return false;
        if (_lost) return null;
        await _sendControl(done);
        continue;
      }
      if (msg['type'] == 'relay_done_ack') {
        final ok = msg['verified'] == true;
        emit(ok ? 'relay_file_sent_ok' : 'relay_hash_mismatch_sender');
        return ok;
      }
      if (msg['type'] == 'relay_retransmit' && rounds < 5) {
        final missing = (msg['missing'] as List? ?? const []).whereType<int>().toList();
        if (missing.isEmpty) continue;
        rounds++;
        emit('relay_retransmit', {'count': missing.length, 'round': rounds});
        try {
          await conn!.sendStream(_frames(missing, (_) {}));
        } catch (_) {
          _lost = true;
        }
        if (_lost) return null;
        await _sendControl(done);
      }
    }
    if (cancelled) return false;
    emit('relay_integrity_timeout');
    return null;
  }
}
