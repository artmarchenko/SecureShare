/// Chunk compression framing, transfer IDs and file-name safety
/// (ports of helpers in app/ws_relay.py).
library;

import 'dart:convert';
import 'dart:io' show ZLibDecoder, ZLibEncoder;
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'constants.dart';
import 'secrets.dart' show hex;

/// flag 0x01 + zlib(level 1) if that saves more than 64 bytes, else flag 0x00 + raw.
Uint8List compressChunk(List<int> data) {
  final c = ZLibEncoder(level: 1).convert(data);
  if (c.length < data.length - 64) {
    return Uint8List.fromList([compressedFlag, ...c]);
  }
  return Uint8List.fromList([rawFlag, ...data]);
}

List<int> decompressChunk(List<int> framed) {
  if (framed.isEmpty) throw const FormatException('empty chunk payload');
  final body = framed.sublist(1);
  return framed[0] == compressedFlag ? ZLibDecoder().convert(body) : body;
}

/// sha256("name|size|sha256")[:32] hex — identifies a file across sessions (resume).
Future<String> transferId(String name, int size, String sha256Hex) async {
  final digest = await Sha256().hash(utf8.encode('$name|$size|$sha256Hex'));
  return hex(digest.bytes).substring(0, 32);
}

const _reserved = {
  'CON', 'PRN', 'AUX', 'NUL',
  'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
  'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
};

// Python's str.strip() / rstrip() whitespace set (Unicode White_Space).
bool _isSpace(int c) =>
    (c >= 0x09 && c <= 0x0d) || (c >= 0x1c && c <= 0x20) || c == 0x85 || c == 0xa0 ||
    c == 0x1680 || (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 ||
    c == 0x202f || c == 0x205f || c == 0x3000;

/// Safe local name for a file name announced by the peer, or null.
/// Mirrors `_safe_file_name` (Python works on code points, so do we).
String? safeFileName(String? raw) {
  if (raw == null || raw.contains('\u0000')) return null;
  final last = raw.replaceAll('\\', '/').split('/').last;
  var runes = [
    for (final c in last.runes) (c < 32 || ':*?"<>|'.runes.contains(c)) ? 0x5f : c,
  ];
  var start = 0, end = runes.length;
  while (start < end && _isSpace(runes[start])) {
    start++;
  }
  while (end > start && _isSpace(runes[end - 1])) {
    end--;
  }
  runes = runes.sublist(start, end);
  while (runes.isNotEmpty && (runes.last == 0x2e || runes.last == 0x20)) {
    runes.removeLast();
  }
  var name = String.fromCharCodes(runes);
  if (name.isEmpty || name == '.' || name == '..') return null;
  if (_reserved.contains(name.split('.').first.toUpperCase())) name = '_$name';
  final out = name.runes.toList();
  return String.fromCharCodes(out.length > 255 ? out.sublist(0, 255) : out);
}
