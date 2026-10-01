// Interop: the Dart transfer engine against the real relay server and the
// Python desktop client from this repository (python -m app.cli).
//
// Needs Python with the repo's requirements (CI installs them). Run alone:
//   flutter test test/interop_test.dart
@Tags(['interop'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:secureshare/transfer/peer.dart';
import 'package:secureshare/transfer/receiver.dart';
import 'package:secureshare/transfer/sender.dart';
import 'package:secureshare/transfer/status.dart';
import 'package:secureshare/transfer/storage.dart';

final repoRoot = p.normalize(p.join(Directory.current.path, '..'));
final python = Platform.environment['PYTHON'] ?? (Platform.isWindows ? 'python' : 'python3');

late Process relayProcess;
late String relayUrl;

Future<void> startRelay() async {
  relayProcess = await Process.start(python, ['scripts/local_relay.py'], workingDirectory: repoRoot);
  final ready = Completer<String>();
  relayProcess.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen((line) {
    if (line.startsWith('READY ') && !ready.isCompleted) ready.complete(line.substring(6).trim());
  });
  relayProcess.stderr.drain<void>();
  relayUrl = await ready.future.timeout(const Duration(seconds: 60));
}

/// TCP proxy in front of the relay that can cut all connections (network outage).
class FlakyProxy {
  late ServerSocket _server;
  final _sockets = <Socket>[];
  late Uri _target;

  Future<String> start(String relay) async {
    _target = Uri.parse(relay);
    _server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    _server.listen((client) async {
      final upstream = await Socket.connect(_target.host, _target.port);
      _sockets..add(client)..add(upstream);
      client.listen(upstream.add, onDone: upstream.destroy, onError: (_) => upstream.destroy());
      upstream.listen(client.add, onDone: client.destroy, onError: (_) => client.destroy());
    });
    return 'ws://127.0.0.1:${_server.port}';
  }

  int dropAll() {
    final n = _sockets.length;
    for (final s in _sockets) {
      s.destroy();
    }
    _sockets.clear();
    return n;
  }

  Future<void> close() => _server.close();
}

String newCode() {
  final r = Random.secure();
  String part() => List.generate(4, (_) => 'abcdefghijklmnopqrstuvwxyz0123456789'[r.nextInt(36)]).join();
  return '${part()}-${part()}';
}

Future<File> randomFile(Directory dir, String name, int size) async {
  final r = Random(size);
  final f = File(p.join(dir.path, name));
  final raf = await f.open(mode: FileMode.write);
  const block = 64 * 1024;
  for (var done = 0; done < size; done += block) {
    final n = min(block, size - done);
    final bytes = Uint8List(n);
    for (var i = 0; i < n; i++) {
      bytes[i] = r.nextInt(256);
    }
    await raf.writeFrom(bytes);
  }
  await raf.close();
  return f;
}

/// Compares by SHA-256 (streams the files instead of loading them).
Future<bool> sameContent(File a, File b) async =>
    (await sha256.bind(a.openRead()).first) == (await sha256.bind(b.openRead()).first);

/// Starts the Python CLI.
Future<Process> startPythonCli(List<String> args) async {
  final proc = await Process.start(python, ['-m', 'app.cli', '--relay', relayUrl, '--quiet', ...args],
      workingDirectory: repoRoot, environment: {'PYTHONIOENCODING': 'utf-8'});
  await proc.stdin.close();
  return proc;
}

/// Waits for a CLI process; returns (exitCode, stdout lines).
Future<(int, List<String>)> finishCli(Process proc) async {
  final out = proc.stdout.transform(utf8.decoder).join();
  unawaited(proc.stderr.drain<void>());
  final code = await proc.exitCode.timeout(const Duration(minutes: 3));
  return (code, const LineSplitter().convert(await out));
}

/// Runs the Python CLI to completion; returns (exitCode, stdout lines).
Future<(int, List<String>)> pythonCli(List<String> args) async => finishCli(await startPythonCli(args));

TransferOptions fastOptions(String url) => TransferOptions(
      relayUrl: url,
      baseDelay: const Duration(milliseconds: 200),
      maxDelay: const Duration(seconds: 1),
      peerWait: const Duration(seconds: 60),
      stepTimeout: const Duration(seconds: 30),
    );

void main() {
  late Directory tmp;

  setUpAll(startRelay);
  tearDownAll(() async {
    await relayProcess.stdin.close();
    relayProcess.kill();
  });
  setUp(() async => tmp = await Directory.systemTemp.createTemp('secureshare-interop-'));
  tearDown(() async {
    try {
      await tmp.delete(recursive: true);
    } catch (_) {}
  });

  test('Dart sender → Python receiver', () async {
    final src = await randomFile(tmp, 'photo.bin', 2 * 1024 * 1024 + 123);
    final inbox = await Directory(p.join(tmp.path, 'pc')).create();
    final code = newCode();
    String? dartCode;
    final py = pythonCli(['--yes', 'receive', code, '--out', inbox.path]);
    final sender = TransferSender(code, LocalFileSource(src), fastOptions(relayUrl),
        onVerify: (c) async {
          dartCode = c;
          return true;
        });
    expect(await sender.send(), isTrue);
    final (exit, lines) = await py;
    expect(exit, 0, reason: lines.join('\n'));
    expect(lines.firstWhere((l) => l.startsWith('VERIFY:')), 'VERIFY: $dartCode');
    expect(await sameContent(src, File(p.join(inbox.path, 'photo.bin'))), isTrue);
  });

  test('Python sender → Dart receiver', () async {
    final src = await randomFile(tmp, 'Звіт 2026.pdf', 1500000);
    final inbox = await Directory(p.join(tmp.path, 'phone')).create();
    final code = newCode();
    String? dartCode;
    final py = pythonCli(['--yes', 'send', src.path, '--code', code]);
    final receiver = TransferReceiver(code, ReceiveFolder(inbox), fastOptions(relayUrl),
        onVerify: (c) async {
          dartCode = c;
          return true;
        });
    final saved = await receiver.receive();
    final (exit, lines) = await py;
    expect(exit, 0, reason: lines.join('\n'));
    expect(lines.firstWhere((l) => l.startsWith('VERIFY:')), 'VERIFY: $dartCode');
    expect(saved, isNotNull);
    expect(p.basename(saved!.path), 'Звіт 2026.pdf');
    expect(await sameContent(src, saved), isTrue);
    expect(inbox.listSync().map((e) => p.basename(e.path)), ['Звіт 2026.pdf']); // no .part/.resume left
  });

  test('Dart ↔ Dart, existing file is not overwritten', () async {
    final src = await randomFile(tmp, 'a.bin', 700000);
    final inbox = await Directory(p.join(tmp.path, 'in')).create();
    await File(p.join(inbox.path, 'a.bin')).writeAsString('precious');
    final code = newCode();
    final states = <TransferState>[];
    final receiver = TransferReceiver(code, ReceiveFolder(inbox), fastOptions(relayUrl),
        onVerify: (_) async => true, onState: states.add);
    final sender = TransferSender(code, LocalFileSource(src), fastOptions(relayUrl), onVerify: (_) async => true);
    final results = await Future.wait([receiver.receive(), sender.send()]);
    final saved = results[0] as File?;
    expect(results[1], isTrue);
    expect(p.basename(saved!.path), 'a (1).bin');
    expect(await File(p.join(inbox.path, 'a.bin')).readAsString(), 'precious');
    expect(states.first, TransferState.connecting);
    expect(states.last, TransferState.done);
  });

  test('receiver rejecting the code stops both sides', () async {
    final src = await randomFile(tmp, 'x.bin', 1000);
    final code = newCode();
    final py = pythonCli(['--yes', 'send', src.path, '--code', code]);
    final keys = <String>[];
    final receiver = TransferReceiver(code, ReceiveFolder(tmp), fastOptions(relayUrl),
        onVerify: (_) async => false, onStatus: (k, _) => keys.add(k));
    expect(await receiver.receive(), isNull);
    expect(keys, contains('relay_verify_rejected'));
    final (exit, _) = await py;
    expect(exit, 1);
  });

  test('network outage mid-transfer: auto-reconnect without asking the code again', () async {
    final proxy = FlakyProxy();
    final url = await proxy.start(relayUrl);
    final src = await randomFile(tmp, 'big.bin', 12 * 1024 * 1024);
    final inbox = await Directory(p.join(tmp.path, 'in')).create();
    final code = newCode();
    var asked = 0;
    final keys = <String>[];
    var dropped = false;
    final receiver = TransferReceiver(code, ReceiveFolder(inbox), fastOptions(url),
        onVerify: (_) async => ++asked > 0,
        onStatus: (k, _) => keys.add(k),
        onProgress: (done, total, _) {
          if (!dropped && done > total * 0.3) {
            dropped = true;
            proxy.dropAll();
          }
        });
    final sender = TransferSender(code, LocalFileSource(src), fastOptions(url), onVerify: (_) async => ++asked > 0);
    final results = await Future.wait([receiver.receive(), sender.send()]).timeout(const Duration(minutes: 2));
    await proxy.close();
    expect(dropped, isTrue);
    expect(results[1], isTrue);
    expect(await sameContent(src, results[0] as File), isTrue);
    expect(asked, 2, reason: 'each side confirmed the code once');
    expect(keys, contains('relay_auto_verify_ok'));
    expect(keys, contains('relay_resume_found'));
  });

  test('cancel, then resume in a new session (Dart → Python)', () async {
    final src = await randomFile(tmp, 'resume.bin', 10 * 1024 * 1024);
    final inbox = await Directory(p.join(tmp.path, 'in')).create();
    final code1 = newCode();
    late TransferReceiver first;
    first = TransferReceiver(code1, ReceiveFolder(inbox), fastOptions(relayUrl),
        onVerify: (_) async => true,
        onProgress: (done, total, _) {
          if (done > total * 0.4) first.cancel();
        });
    final py1 = await startPythonCli(['--yes', 'send', src.path, '--code', code1]);
    expect(await first.receive(), isNull);
    // the Python sender now treats this as a network drop and would keep
    // reconnecting for minutes — stop it, as a user would close the app
    py1.kill();
    await py1.exitCode;
    expect(File(p.join(inbox.path, 'resume.bin.part.resume')).existsSync(), isTrue);

    final code2 = newCode();
    final keys = <String>[];
    final py2 = pythonCli(['--yes', 'send', src.path, '--code', code2]);
    final second = TransferReceiver(code2, ReceiveFolder(inbox), fastOptions(relayUrl),
        onVerify: (_) async => true, onStatus: (k, _) => keys.add(k));
    final saved = await second.receive();
    final (exit, lines) = await py2;
    expect(exit, 0, reason: lines.join('\n'));
    expect(keys, contains('relay_resume_found'));
    expect(await sameContent(src, saved!), isTrue);
    expect(File(p.join(inbox.path, 'resume.bin.part.resume')).existsSync(), isFalse);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('larger file Dart → Python (backpressure, speed)', () async {
    final src = await randomFile(tmp, 'large.bin', 64 * 1024 * 1024);
    final inbox = await Directory(p.join(tmp.path, 'pc')).create();
    final code = newCode();
    final py = pythonCli(['--yes', 'receive', code, '--out', inbox.path]);
    final sw = Stopwatch()..start();
    final sender = TransferSender(code, LocalFileSource(src), fastOptions(relayUrl), onVerify: (_) async => true);
    expect(await sender.send(), isTrue);
    final (exit, _) = await py;
    // ignore: avoid_print
    print('  64 MiB Dart→Python via local relay: ${sw.elapsedMilliseconds} ms, '
        'RSS ${(ProcessInfo.maxRss / 1048576).toStringAsFixed(0)} MiB max');
    expect(exit, 0);
    expect(await sameContent(src, File(p.join(inbox.path, 'large.bin'))), isTrue);
  }, timeout: const Timeout(Duration(minutes: 5)));
}
