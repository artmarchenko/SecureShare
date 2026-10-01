/// File access for transfers: a readable source (sender) and a receive
/// folder with .part files, resume manifests and no-overwrite naming
/// (same files and JSON as the desktop app).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;
import 'package:path/path.dart' as p;

import '../protocol/frames.dart' show safeFileName;

/// A file being sent. Random access is needed for resume and retransmit.
abstract class FileSource {
  String get name;
  Future<int> length();
  Future<List<int>> read(int offset, int length);
  Future<String> sha256Hex();
  Future<void> close();
}

class LocalFileSource implements FileSource {
  /// [name] overrides the file's own name (e.g. a /proc/self/fd/N path on Android).
  LocalFileSource(this.file, {String? name}) : _name = name; // ignore: prefer_initializing_formals
  final File file;
  final String? _name;
  RandomAccessFile? _raf;

  @override
  String get name => _name ?? p.basename(file.path);

  @override
  Future<int> length() => file.length();

  @override
  Future<List<int>> read(int offset, int length) async {
    final raf = _raf ??= await file.open();
    await raf.setPosition(offset);
    return raf.read(length);
  }

  @override
  Future<String> sha256Hex() async => (await crypto.sha256.bind(file.openRead()).first).toString();

  @override
  Future<void> close() async {
    await _raf?.close();
    _raf = null;
  }
}

const resumeMaxAge = Duration(days: 7);

/// Resume manifest — JSON identical to the desktop app's `.part.resume`.
class ResumeManifest {
  ResumeManifest({
    required this.transferId,
    required this.fileName,
    required this.fileSize,
    required this.sha256,
    required this.chunkSize,
    required this.totalChunks,
    required this.received,
  });

  final String transferId, fileName, sha256;
  final int fileSize, chunkSize, totalChunks;
  final Set<int> received;

  Map<String, Object> toJson() => {
        'transfer_id': transferId,
        'file_name': fileName,
        'file_size': fileSize,
        'file_sha256': sha256,
        'chunk_size': chunkSize,
        'total_chunks': totalChunks,
        'received_chunks': received.toList()..sort(),
        'timestamp': DateTime.now().millisecondsSinceEpoch / 1000,
      };
}

class ReceiveFolder {
  ReceiveFolder(this.dir);
  final Directory dir;

  File partFile(String name) => File(p.join(dir.path, '$name.part'));
  File manifestFile(String name) => File(p.join(dir.path, '$name.part.resume'));

  /// True if [name] resolves directly inside the folder.
  bool containsName(String name) => p.equals(p.dirname(p.normalize(p.join(dir.path, name))), dir.path);

  Future<void> saveManifest(ResumeManifest m) async {
    final f = manifestFile(m.fileName);
    final tmp = File('${f.path}.tmp');
    try {
      await tmp.writeAsString(jsonEncode(m.toJson()));
      await tmp.rename(f.path);
    } catch (_) {
      try {
        await tmp.delete();
      } catch (_) {}
    }
  }

  /// A still-valid manifest for this exact transfer, or null.
  Future<ResumeManifest?> loadManifest(String name, String transferId) async {
    final f = manifestFile(name);
    if (!await f.exists()) return null;
    Map<String, dynamic> data;
    try {
      data = jsonDecode(await f.readAsString()) as Map<String, dynamic>;
    } catch (_) {
      await _quietDelete(f);
      return null;
    }
    if (data['transfer_id'] != transferId) return null;
    final ts = (data['timestamp'] as num?)?.toDouble() ?? 0;
    final age = DateTime.now().difference(DateTime.fromMillisecondsSinceEpoch((ts * 1000).round()));
    if (age > resumeMaxAge) {
      await _quietDelete(f);
      return null;
    }
    return ResumeManifest(
      transferId: transferId,
      fileName: name,
      fileSize: data['file_size'] as int,
      sha256: data['file_sha256'] as String,
      chunkSize: data['chunk_size'] as int,
      totalChunks: data['total_chunks'] as int,
      received: {for (final c in data['received_chunks'] as List) c as int},
    );
  }

  Future<void> deleteManifest(String name) => _quietDelete(manifestFile(name));

  /// `name`, or `name (1).ext`, `name (2).ext` … — never overwrite a file.
  Future<File> uniqueTarget(String name) async {
    final first = File(p.join(dir.path, name));
    if (!await first.exists()) return first;
    final stem = p.basenameWithoutExtension(name), ext = p.extension(name);
    for (var n = 1; n < 10000; n++) {
      final f = File(p.join(dir.path, '$stem ($n)$ext'));
      if (!await f.exists()) return f;
    }
    throw FileSystemException('too many files named like $name', dir.path);
  }

  static Future<void> _quietDelete(File f) async {
    try {
      if (await f.exists()) await f.delete();
    } catch (_) {}
  }
}

/// Exposed so the receiver validates names exactly like the desktop app.
String? sanitizeIncomingName(Object? raw) => raw is String ? safeFileName(raw) : null;
