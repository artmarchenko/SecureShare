// Translations: the desktop copy is up to date, all three languages have the
// same keys and placeholders, and every key the code uses exists.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:secureshare/app/i18n.dart';

Map<String, String> _read(String path) => {
      for (final e in (jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>).entries)
        if (e.value is String) e.key: e.value as String,
    };

Set<String> _placeholders(String text) => {for (final m in RegExp(r'\{(\w+)').allMatches(text)) m[1]!};

void main() {
  final mobile = {for (final l in languages) l: _read('assets/lang/$l.json')};
  final desktop = {for (final l in languages) l: _read('assets/lang/desktop/$l.json')};

  test('desktop texts are an exact copy of app/lang', () {
    for (final l in languages) {
      expect(File('assets/lang/desktop/$l.json').readAsBytesSync(), File('../app/lang/$l.json').readAsBytesSync(),
          reason: 'app/lang/$l.json changed: copy it to mobile/assets/lang/desktop/');
    }
  });

  test('mobile texts: same keys and placeholders in every language', () {
    for (final l in languages) {
      expect(mobile[l]!.keys.toSet(), mobile['en']!.keys.toSet(), reason: l);
      for (final k in mobile['en']!.keys) {
        expect(_placeholders(mobile[l]![k]!), _placeholders(mobile['en']![k]!), reason: '$l: $k');
        expect(mobile[l]![k]!.trim(), isNotEmpty, reason: '$l: $k');
      }
      expect(mobile[l]!.keys.where((k) => !k.startsWith('m_')), isEmpty,
          reason: 'mobile-only keys start with m_ so they never shadow desktop ones');
    }
  });

  test('every key used in the code exists in every language', () {
    final literal = RegExp(
        r"""['"]((?:m|state|relay|help|diag|btn|verify|transfer|log|unit|eta|recv|send|file|speed|copyright)_[a-z0-9_]+)['"]""");
    // protocol message types and manifest fields, not texts
    const protocolNames = {
      'relay_meta', 'relay_meta_ack', 'relay_done', 'relay_done_ack', 'verify_reject',
      'transfer_id', 'file_name', 'file_size', 'file_sha256',
    };
    final used = <String, String>{};
    for (final f in Directory('lib').listSync(recursive: true).whereType<File>().where((f) => f.path.endsWith('.dart'))) {
      for (final m in literal.allMatches(f.readAsStringSync())) {
        if (!protocolNames.contains(m[1])) used[m[1]!] = p.relative(f.path);
      }
    }
    expect(used.length, greaterThan(80), reason: 'the scan should find the status keys too');
    for (final l in languages) {
      final all = {...desktop[l]!, ...mobile[l]!};
      final missing = {for (final e in used.entries) if (!all.containsKey(e.key)) e.key: e.value};
      expect(missing, isEmpty, reason: 'missing in $l');
    }
  });
}
