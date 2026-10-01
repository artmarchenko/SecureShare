/// Receiving a file â€” port of `VPSRelayReceiver` in app/ws_relay.py
/// (_on_meta / _on_data / _on_done).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto_hash;

import '../protocol/constants.dart';
import '../protocol/frames.dart';
import 'peer.dart';
import 'storage.dart';

const resumeSaveInterval = 64; // save the manifest every N chunks

class _Incoming {
  String? name;
  int size = 0;
  String sha256 = '';
  String transferId = '';
  int chunkSz = chunkSize;
  int totalChunks = 0;
  Set<int> received = {};
  int bytes = 0;
  int sinceSave = 0;
  RandomAccessFile? part;
  final sw = Stopwatch()..start();
  Duration lastReport = Duration.zero;

  ResumeManifest manifest() => ResumeManifest(
      transferId: transferId, fileName: name!, fileSize: size, sha256: sha256,
      chunkSize: chunkSz, totalChunks: totalChunks, received: received);
}

class TransferReceiver extends RelayPeer {
  TransferReceiver(super.code, this.folder, super.options,
      {super.onStatus, super.onState, super.onProgress, required super.onVerify});

  final ReceiveFolder folder;

  @override
  String get role => roleReceiver;
  @override
  String get waitingKey => 'relay_waiting_sender';

  /// The saved file, or null on failure / cancel.
  Future<File?> receive() => runWithReconnect<File?>(_attempt, null);

  Future<(Attempt, File?)> _attempt(bool isReconnect) async {
    final failed = await openSession(isReconnect);
    if (failed != null) return (failed, null);
    emit('relay_waiting_meta');
    final rx = _Incoming();
    try {
      while (!cancelled) {
        final Uint8List raw;
        try {
          raw = await conn!.receive(options.stepTimeout);
        } catch (_) {
          // connection lost: worth retrying once data has started to flow
          final retry = rx.name != null && rx.received.isNotEmpty && !cancelled;
          return (retry ? Attempt.retry : Attempt.fatal, null);
        }
        if (raw.isEmpty) continue;
        if (raw[0] == frameControl) {
          Map<String, dynamic> msg;
          try {
            final decoded = jsonDecode(utf8.decode(await crypto!.decrypt(raw.sublist(1), utf8.encode('C'))));
            if (decoded is! Map<String, dynamic>) continue;
            msg = decoded;
          } catch (_) {
            continue;
          }
          if (msg['type'] == 'relay_meta') {
            if (!await _onMeta(msg, rx)) return (Attempt.fatal, null);
          } else if (msg['type'] == 'relay_done') {
            final done = await _onDone(msg, rx);
            if (done != null) return done;
          }
        } else if (raw[0] == frameData && rx.name != null) {
          await _onData(raw, rx);
        }
      }
      return (Attempt.fatal, null); // cancelled
    } catch (e) {
      emit('transfer_error_generic', {'error': e.toString()});
      final retry = rx.name != null && rx.received.isNotEmpty;
      return (retry ? Attempt.retry : Attempt.fatal, null);
    } finally {
      await rx.part?.close();
      rx.part = null;
      if (rx.name != null && rx.transferId.isNotEmpty && rx.received.isNotEmpty &&
          rx.received.length < rx.totalChunks) {
        emit('relay_progress_saved', {'received': rx.received.length, 'total': rx.totalChunks});
        await folder.saveManifest(rx.manifest());
      }
    }
  }

  Future<bool> _onMeta(Map<String, dynamic> msg, _Incoming rx) async {
    final size = msg['size'];
    final rawChunk = msg['chunk_size'];

    final name = sanitizeIncomingName(msg['name']);
    if (name == null) {
      emit('relay_unsafe_filename');
      return false;
    }
    if (!folder.containsName(name)) {
      emit('relay_path_traversal');
      return false;
    }
    if (size is! int || size <= 0) {
      emit('relay_invalid_filesize');
      return false;
    }
    if (size > maxFileSize) {
      emit('relay_file_too_large', {
        'size': (size / (1 << 30)).toStringAsFixed(1), 'limit': (maxFileSize / (1 << 30)).toStringAsFixed(0),
      });
      return false;
    }
    // unreasonable chunk sizes fall back to the default; total is recomputed from the size
    final int chunk = (rawChunk is int && rawChunk > 0 && rawChunk <= 4 * 1024 * 1024) ? rawChunk : chunkSize;
    final int total = (size + chunk - 1) ~/ chunk;

    rx
      ..name = name
      ..size = size
      ..sha256 = '${msg['sha256'] ?? ''}'
      ..transferId = '${msg['transfer_id'] ?? ''}'
      ..chunkSz = chunk
      ..totalChunks = total;

    // Resume detection
    final part = folder.partFile(name);
    final manifest = rx.transferId.isEmpty ? null : await folder.loadManifest(name, rx.transferId);
    var resume = false;
    if (manifest != null && await part.exists() && manifest.chunkSize == chunk && manifest.totalChunks == total) {
      try {
        rx.part = await part.open(mode: FileMode.append);
        resume = true;
      } catch (e) {
        emit('relay_part_open_error', {'error': e.toString()});
      }
    }
    if (resume) {
      rx.received = manifest!.received;
      var bytes = rx.received.length * chunk;
      if (rx.received.contains(total - 1)) bytes = bytes - chunk + (size - (total - 1) * chunk);
      rx.bytes = bytes.clamp(0, size).toInt();
      emit('relay_resume_found',
          {'received': rx.received.length, 'total': total, 'mb': (rx.bytes / 1048576).toStringAsFixed(1)});
      emit('relay_receiving_resume',
          {'filename': name, 'size': size, 'pct': (rx.bytes / size * 100).toStringAsFixed(0)});
    } else {
      try {
        rx.part = await part.open(mode: FileMode.write);
        await rx.part!.truncate(size); // pre-allocate
      } catch (e) {
        emit('relay_file_create_error', {'error': e.toString()});
        return false;
      }
      emit('relay_receiving', {'filename': name, 'size': size});
    }
    final ack = <String, Object>{'type': 'relay_meta_ack'};
    if (resume && rx.received.isNotEmpty) {
      ack['resume'] = true;
      ack['received_chunks'] = rx.received.toList()..sort();
    }
    await _sendControl(ack);
    rx.sw.reset();
    if (resume) onProgress?.call(rx.bytes, size, 0);
    return true;
  }

  Future<void> _onData(Uint8List raw, _Incoming rx) async {
    if (raw.length < 5) return;
    final seq = ByteData.sublistView(raw, 1, 5).getUint32(0);
    if (!rx.received.contains(seq) && seq < rx.totalChunks) {
      List<int> chunk;
      try {
        // the chunk number is authenticated: a moved/relabelled frame fails here
        chunk = decompressChunk(await crypto!.decrypt(raw.sublist(5), [...utf8.encode('D'), ...raw.sublist(1, 5)]));
      } catch (_) {
        return;
      }
      await rx.part!.setPosition(seq * rx.chunkSz);
      await rx.part!.writeFrom(chunk);
      rx.received.add(seq);
      rx.bytes += chunk.length;
      rx.sinceSave++;
    }
    if (rx.sinceSave >= resumeSaveInterval && rx.transferId.isNotEmpty) {
      await rx.part!.flush();
      await folder.saveManifest(rx.manifest());
      rx.sinceSave = 0;
    }
    if (rx.sw.elapsed - rx.lastReport >= const Duration(milliseconds: 500)) {
      rx.lastReport = rx.sw.elapsed;
      onProgress?.call(rx.bytes, rx.size, rx.bytes / (rx.sw.elapsedMicroseconds / 1e6 + 1e-9));
    }
  }

  Future<(Attempt, File?)?> _onDone(Map<String, dynamic> msg, _Incoming rx) async {
    if (rx.name == null) return null;
    rx.sha256 = '${msg['sha256'] ?? rx.sha256}';
    final missing = [for (var i = 0; i < rx.totalChunks; i++) if (!rx.received.contains(i)) i];
    if (missing.isNotEmpty) {
      if (rx.transferId.isNotEmpty) await folder.saveManifest(rx.manifest());
      for (var i = 0; i < missing.length; i += 1000) {
        await _sendControl({'type': 'relay_retransmit', 'missing': missing.sublist(i, (i + 1000).clamp(0, missing.length))});
      }
      emit('relay_request_retransmit', {'count': missing.length});
      return null;
    }
    await rx.part!.flush();
    await rx.part!.close();
    rx.part = null;
    emit('relay_verifying_sha');
    final part = folder.partFile(rx.name!);
    final actual = (await crypto_hash.sha256.bind(part.openRead()).first).toString();
    final verified = actual == rx.sha256;
    await _sendControl({'type': 'relay_done_ack', 'verified': verified});
    await Future<void>.delayed(const Duration(milliseconds: 300)); // let the ack leave
    await folder.deleteManifest(rx.name!);
    if (!verified) {
      emit('relay_hash_mismatch_recv');
      try {
        await part.delete();
      } catch (_) {}
      return (Attempt.fatal, null);
    }
    final target = await folder.uniqueTarget(rx.name!);
    if (target.path.split(Platform.pathSeparator).last != rx.name) {
      emit('relay_file_renamed', {'filename': target.uri.pathSegments.last});
    }
    final saved = await part.rename(target.path);
    final secs = rx.sw.elapsedMicroseconds / 1e6;
    emit('relay_saved', {
      'filename': target.uri.pathSegments.last,
      'speed': (rx.size / (secs > 0 ? secs : 1) / 1048576).toStringAsFixed(1),
    });
    rx.received = {};
    return (Attempt.success, saved);
  }

  Future<void> _sendControl(Map<String, Object?> msg) async {
    try {
      conn!.sendBinary([frameControl, ...await crypto!.encrypt(utf8.encode(jsonEncode(msg)), utf8.encode('C'))]);
    } catch (_) {}
  }
}

