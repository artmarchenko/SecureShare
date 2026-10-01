// Memory behaviour of the sender on a large file (Dart → Python receiver).
// The RSS must stay flat while the transfer progresses — the file must not
// be buffered in memory.
@Tags(['interop'])
library;

import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:secureshare/transfer/sender.dart';
import 'package:secureshare/transfer/storage.dart';

import 'interop_test.dart' as interop;

void main() {
  setUpAll(interop.startRelay);
  tearDownAll(() async {
    await interop.relayProcess.stdin.close();
    interop.relayProcess.kill();
  });

  test('sending 256 MiB keeps memory flat', () async {
    final tmp = await Directory.systemTemp.createTemp('secureshare-mem-');
    try {
      final src = File(p.join(tmp.path, 'big.bin'));
      final raf = await src.open(mode: FileMode.write);
      final block = List<int>.generate(1 << 20, (i) => (i * 2654435761) >> 7 & 0xff);
      for (var i = 0; i < 256; i++) {
        block[0] = i;
        await raf.writeFrom(block);
      }
      await raf.close();
      final inbox = await Directory(p.join(tmp.path, 'pc')).create();
      final code = interop.newCode();
      final py = interop.pythonCli(['--yes', 'receive', code, '--out', inbox.path]);
      final samples = <int, int>{}; // percent → RSS MiB
      final sw = Stopwatch()..start();
      final sender = TransferSender(code, LocalFileSource(src), interop.fastOptions(interop.relayUrl),
          onVerify: (_) async => true,
          onProgress: (done, total, _) => samples.putIfAbsent(done * 10 ~/ total * 10, () => ProcessInfo.currentRss >> 20));
      expect(await sender.send(), isTrue);
      final (exit, _) = await py;
      expect(exit, 0);
      // ignore: avoid_print
      print('  256 MiB in ${sw.elapsedMilliseconds} ms; RSS by progress %: $samples');
      final sent = await sha256.bind(src.openRead()).first;
      final got = await sha256.bind(File(p.join(inbox.path, 'big.bin')).openRead()).first;
      expect(got, sent);
      final early = samples.entries.where((e) => e.key >= 10).first.value;
      final late = samples.entries.last.value;
      expect(late - early, lessThan(150), reason: 'RSS grew with the amount sent: $samples');
    } finally {
      await tmp.delete(recursive: true);
    }
  }, timeout: const Timeout(Duration(minutes: 10)));
}
