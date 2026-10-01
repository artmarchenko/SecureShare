/// Self-test of an installed build — like the desktop's `--self-test`.
/// The release workflow starts the signed APK on an emulator with
/// `--ez selftest true` and waits for "SECURESHARE_SELFTEST OK" in logcat:
/// it catches what only breaks in release builds (code shrinking, missing
/// assets, native code).
library;

import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as p;

import '../protocol/constants.dart' show roleReceiver, roleSender;
import '../protocol/crypto_session.dart';
import '../protocol/secrets.dart';
import '../transfer/handshake.dart' show appVersion;
import 'device.dart';
import 'i18n.dart';

/// Failures (empty = all good).
Future<List<String>> runSelfTest(Device device, Strings strings) async {
  final problems = <String>[];
  Future<void> check(String name, Future<bool> Function() body) async {
    try {
      if (!await body()) problems.add(name);
    } catch (e) {
      problems.add('$name: $e');
    }
  }

  // scrypt through the native channel + HKDF: tests/vectors/protocol_v2.json
  await check('session secrets',
      () async => (await SessionSecrets.fromCode('ab12-cd34')).roomId == '43bedc52b60ba9e9cccade2940ba95bc');
  await check('key exchange + AES-GCM', () async {
    final secrets = await SessionSecrets.fromCode('selftest-0000');
    final a = await CryptoSession.create(secrets, roleSender);
    final b = await CryptoSession.create(secrets, roleReceiver);
    await a.deriveSharedKey(b.publicKey);
    await b.deriveSharedKey(a.publicKey);
    final box = await a.encrypt([1, 2, 3], [7]);
    return listEquals(await b.decrypt(box, [7]), [1, 2, 3]) &&
        await a.verificationCode() == await b.verificationCode();
  });
  await check('translations', () async => [
        for (final l in languages) strings.table(l)
      ].every((t) => t['m_send'] != null && t['relay_saved'] != null));
  await check('receive folder', () async {
    final f = File(p.join((await device.receiveDir()).path, '.secureshare-selftest'));
    await f.writeAsString('ok');
    final ok = await f.readAsString() == 'ok';
    await f.delete();
    return ok;
  });
  return problems;
}

Future<void> reportSelfTest(Device device, Strings strings) async {
  final problems = await runSelfTest(device, strings);
  // print, not debugPrint: must reach logcat in release builds
  // ignore: avoid_print
  print(problems.isEmpty
      ? 'SECURESHARE_SELFTEST OK $appVersion'
      : 'SECURESHARE_SELFTEST FAIL ${problems.join('; ')}');
}
