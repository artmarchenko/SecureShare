/// User settings, a small JSON file in the app's private folder.
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as p;

class Settings extends ChangeNotifier {
  Settings(this._file, this._data);

  final File? _file;
  final Map<String, Object?> _data;

  static Future<Settings> load(Directory dir) async {
    final f = File(p.join(dir.path, 'settings.json'));
    try {
      final data = jsonDecode(await f.readAsString());
      if (data is Map<String, Object?>) return Settings(f, data);
    } catch (_) {}
    return Settings(f, {});
  }

  /// In-memory only (tests).
  factory Settings.memory() => Settings(null, {});

  /// Chosen language, or null = follow the system.
  String? get language => _data['language'] as String?;

  Future<void> setLanguage(String? value) async {
    if (value == null) {
      _data.remove('language');
    } else {
      _data['language'] = value;
    }
    notifyListeners();
    await _save();
  }

  Future<void> _save() async {
    final f = _file;
    if (f == null) return;
    try {
      final tmp = File('${f.path}.tmp');
      await tmp.writeAsString(jsonEncode(_data));
      await tmp.rename(f.path);
    } catch (_) {}
  }
}
