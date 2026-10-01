// Developer benchmark: how long the protocol's expensive steps take on a
// device. Run: flutter run --release -t lib/bench_main.dart -d <device>
// Results are printed to the log (adb logcat -s flutter).

import 'package:flutter/material.dart';
import 'package:secureshare/protocol/constants.dart';
import 'package:secureshare/protocol/crypto_session.dart';
import 'package:secureshare/protocol/frames.dart';
import 'package:secureshare/protocol/secrets.dart';

Future<String> runBenchmark() async {
  final lines = <String>[];
  const expectedMaster = '12f605f586268fc6a02665376ce1d82fd4bbe28b8d2760fb21a639443fb3f104';  // from tests/vectors/protocol_v2.json
  var sw = Stopwatch()..start();
  final native = await scryptMaster('ab12-cd34');
  lines.add('scrypt (default path): ${sw.elapsedMilliseconds} ms, matches vector: ${hex(native) == expectedMaster}');
  sw = Stopwatch()..start();
  final dart = scryptMasterDart('ab12-cd34');
  lines.add('scrypt (pure Dart): ${sw.elapsedMilliseconds} ms, matches vector: ${hex(dart) == expectedMaster}');
  final secrets = await SessionSecrets.fromMaster(native);

  sw = Stopwatch()..start();
  final s = await CryptoSession.create(secrets, roleSender);
  final r = await CryptoSession.create(secrets, roleReceiver);
  await s.deriveSharedKey(r.publicKey);
  await r.deriveSharedKey(s.publicKey);
  lines.add('x25519+hkdf (both sides): ${sw.elapsedMilliseconds} ms, code ${await s.verificationCode()}');

  final chunk = List<int>.generate(chunkSize, (i) => (i * 2654435761) & 0xff);
  sw = Stopwatch()..start();
  const n = 8;
  for (var i = 0; i < n; i++) {
    final payload = compressChunk(chunk);
    final enc = await s.encrypt(payload, [0x44, 0, 0, 0, i]);
    await r.decrypt(enc, [0x44, 0, 0, 0, i]);
  }
  final ms = sw.elapsedMilliseconds;
  lines.add('8 x 512 KiB compress+encrypt+decrypt: $ms ms (${(n * 0.5 / (ms / 1000)).toStringAsFixed(1)} MiB/s)');
  for (final l in lines) {
    debugPrint('SECURESHARE_BENCH $l');
  }
  return lines.join('\n');
}

void main() => runApp(const MaterialApp(home: _Bench()));

class _Bench extends StatefulWidget {
  const _Bench();
  @override
  State<_Bench> createState() => _BenchState();
}

class _BenchState extends State<_Bench> {
  String _text = 'running…';
  @override
  void initState() {
    super.initState();
    runBenchmark().then((t) => setState(() => _text = t));
  }

  @override
  Widget build(BuildContext context) =>
      Scaffold(body: Center(child: Padding(padding: const EdgeInsets.all(24), child: Text(_text))));
}
