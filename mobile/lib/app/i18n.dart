/// Translations: the desktop texts (assets/lang/desktop/*.json, a copy of
/// app/lang — transfer statuses, verification, help) plus the texts of the
/// mobile screens (assets/lang/*.json, keys `m_*`).
library;

import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

const languages = ['uk', 'en', 'de'];
const languageNames = {'uk': 'Українська', 'en': 'English', 'de': 'Deutsch'};

/// The language for a device locale when the user has not chosen one.
String languageForLocale(String? languageCode) =>
    languages.contains(languageCode) ? languageCode! : 'en';

class Strings extends ChangeNotifier {
  Strings(this._all, String lang) : _lang = languages.contains(lang) ? lang : 'en';

  final Map<String, Map<String, String>> _all;
  String _lang;

  String get lang => _lang;
  Map<String, String> table(String lang) => _all[lang] ?? const {};

  set lang(String value) {
    if (value == _lang || !languages.contains(value)) return;
    _lang = value;
    notifyListeners();
  }

  static Future<Strings> load(AssetBundle bundle, String lang) async {
    final all = <String, Map<String, String>>{};
    for (final l in languages) {
      final merged = <String, String>{};
      for (final path in ['assets/lang/desktop/$l.json', 'assets/lang/$l.json']) {
        final data = jsonDecode(await bundle.loadString(path)) as Map<String, dynamic>;
        data.forEach((k, v) {
          if (v is String) merged[k] = v;
        });
      }
      all[l] = merged;
    }
    return Strings(all, lang);
  }

  /// The text for [key] (English, then the key itself, if missing).
  /// Placeholders as in the desktop files: `{name}` and `{name:02d}`.
  String t(String key, [Map<String, Object?> args = const {}]) {
    final raw = _all[_lang]?[key] ?? _all['en']?[key] ?? key;
    if (args.isEmpty) return raw;
    return raw.replaceAllMapped(RegExp(r'\{(\w+)(?::0?(\d+)d)?\}'), (m) {
      if (!args.containsKey(m[1])) return m[0]!;
      var value = _arg(m[1]!, args[m[1]]);
      final width = m[2];
      if (width != null) value = value.padLeft(int.parse(width), '0');
      return value;
    });
  }

  String _arg(String name, Object? value) {
    if (name == 'size' && value is int) return size(value);
    return '$value';
  }

  // ── Formatting (same as app/format.py) ──

  String size(num bytes) {
    var b = bytes.toDouble();
    for (final unit in ['unit_b', 'unit_kb', 'unit_mb', 'unit_gb', 'unit_tb']) {
      if (b.abs() < 1024) return '${b.toStringAsFixed(1)} ${t(unit)}';
      b /= 1024;
    }
    return '${b.toStringAsFixed(1)} ${t('unit_pb')}';
  }

  String speed(double bytesPerSecond) => '${size(bytesPerSecond)}${t('speed_suffix')}';

  String eta(double seconds) {
    if (seconds.isNaN || seconds < 0 || seconds > 360000) return '—';
    final total = seconds.toInt();
    final h = total ~/ 3600, m = total % 3600 ~/ 60, s = total % 60;
    if (h > 0) return t('eta_hours', {'h': h, 'm': m});
    if (m > 0) return t('eta_minutes', {'m': m, 's': s});
    return t('eta_seconds', {'s': s});
  }
}

/// Desktop texts are wrapped by hand for a fixed-width window; on a phone
/// let them flow. A single line break before a word is joined; paragraph
/// breaks and breaks before list items (numbers, bullets, emoji) stay.
String unwrap(String text) => text.replaceAllMapped(
    RegExp(r'(?<!\n)\n[ \t]*(?=[\p{L}(«„"“])', unicode: true), (_) => ' ');

/// Drops a leading emoji/symbol ("✅ Codes match" → "Codes match") for
/// places that have their own icon, like buttons.
String plain(String text) => text.replaceFirst(RegExp(r'^[^\p{L}\p{N}«„"(]+', unicode: true), '');
