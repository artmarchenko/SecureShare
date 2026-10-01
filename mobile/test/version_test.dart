// One version everywhere: pubspec (versionName/versionCode), the version the
// app reports to its peer, and the release tag (checked by release-android.yml).
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:secureshare/transfer/handshake.dart' show appVersion;

void main() {
  test('pubspec version = appVersion; versionCode = major*10000 + minor*100 + patch', () {
    final m = RegExp(r'^version:\s*(\d+)\.(\d+)\.(\d+)\+(\d+)\s*$', multiLine: true)
        .firstMatch(File('pubspec.yaml').readAsStringSync())!;
    final (major, minor, patch, code) = (int.parse(m[1]!), int.parse(m[2]!), int.parse(m[3]!), int.parse(m[4]!));
    expect('$major.$minor.$patch', appVersion);
    expect(code, major * 10000 + minor * 100 + patch, reason: 'versionCode must grow with every release');
  });
}
