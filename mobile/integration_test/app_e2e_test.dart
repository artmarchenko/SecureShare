// End-to-end on an emulator: the real app and transfer engine against a
// local relay and the desktop client (python -m app.cli). Started by
// scripts/android_e2e.py, which runs the PC side and presses Home mid-transfer.
//
// The system file picker can't be driven from a test, so "Choose file"
// returns a file the test creates; everything after that is the real thing.
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:path/path.dart' as p;
import 'package:secureshare/app/controller.dart';
import 'package:secureshare/app/device.dart';
import 'package:secureshare/main.dart';
import 'package:secureshare/transfer/storage.dart';
import 'package:secureshare/ui/app.dart';

const recvCode = String.fromEnvironment('E2E_RECV_CODE');
const recvSha = String.fromEnvironment('E2E_RECV_SHA');
const sendCode = String.fromEnvironment('E2E_SEND_CODE');
const sendMb = int.fromEnvironment('E2E_SEND_MB', defaultValue: 64);

/// The real device, except that "Choose file" returns [file].
class _TestPickDevice extends NativeDevice {
  File? file;

  @override
  Future<PickedFile?> pickFile() async {
    final f = file!;
    return PickedFile(handle: -1, name: p.basename(f.path), size: await f.length());
  }

  @override
  FileSource fileSource(PickedFile picked) => picked.handle == -1 ? LocalFileSource(file!) : super.fileSource(picked);

  @override
  Future<void> releaseFile(int handle) async {
    if (handle != -1) await super.releaseFile(handle);
  }
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  late AppServices app;
  final device = _TestPickDevice();

  /// Waits (in real time) for the controller to reach [done].
  Future<void> waitFor(WidgetTester tester, bool Function(TransferController c) done,
      {Duration timeout = const Duration(minutes: 5)}) async {
    final end = DateTime.now().add(timeout);
    while (!done(app.controller)) {
      if (DateTime.now().isAfter(end)) fail('timed out; log:\n${app.controller.log.map((l) => l.key).join('\n')}');
      // not tester.pump(): no frames are drawn while the app is in the background
      await Future<void>.delayed(const Duration(milliseconds: 200));
    }
    await tester.pump();
  }

  Future<void> confirmCode(WidgetTester tester) async {
    await waitFor(tester, (c) => c.verifyCode != null);
    // ignore: avoid_print
    print('E2E:VERIFY ${app.controller.verifyCode}');
    for (var i = 0; i < 5; i++) {
      await tester.pump(const Duration(milliseconds: 100)); // the progress bar animates: no pumpAndSettle
    }
    await tester.tap(find.byKey(const Key('codes-match')));
    await tester.pump();
  }

  setUpAll(() async {
    app = await createServices(device: device, newCode: () => sendCode);
  });

  testWidgets('receive from the PC via an invitation link, app in the background mid-transfer', (tester) async {
    await tester.pumpWidget(SecureShareApp(services: app));
    await tester.pumpAndSettle();
    // ignore: avoid_print
    print('E2E:RECEIVE_START'); // the runner starts the PC sender and opens https://…/r#<code> via Android
    final field = find.byKey(const Key('code-input'));
    final end = DateTime.now().add(const Duration(seconds: 60));
    while (field.evaluate().isEmpty || tester.widget<TextField>(field).controller!.text != recvCode) {
      if (DateTime.now().isAfter(end)) fail('the invitation link did not fill in the code');
      await Future<void>.delayed(const Duration(milliseconds: 200));
      await tester.pump();
    }
    expect(find.byKey(const Key('invite-hint')), findsOneWidget);
    await tester.tap(find.byKey(const Key('receive')));
    await confirmCode(tester);
    // ignore: avoid_print
    print('E2E:TRANSFERRING');
    await waitFor(tester, (c) => c.phase == Phase.finished);
    expect(app.controller.outcome, Outcome.success, reason: app.controller.log.map((l) => l.key).join('\n'));
    final saved = app.controller.savedFile!;
    expect((await sha256.bind(saved.openRead()).first).toString(), recvSha);
    // ignore: avoid_print
    print('E2E:RECEIVED ${saved.path}');
    await tester.pump(const Duration(milliseconds: 300));
    expect(find.byKey(const Key('open-file')), findsOneWidget);
    await tester.tap(find.byKey(const Key('done')));
    await tester.pumpAndSettle();
  });

  testWidgets('send to the PC', (tester) async {
    final dir = await Directory.systemTemp.createTemp('e2e');
    final f = File(p.join(dir.path, 'from-phone.bin'));
    final r = Random(42);
    final sink = f.openWrite();
    for (var i = 0; i < sendMb; i++) {
      sink.add(List<int>.generate(1 << 20, (_) => r.nextInt(256)));
    }
    await sink.close();
    device.file = f;
    // ignore: avoid_print
    print('E2E:SENT_SHA ${(await sha256.bind(f.openRead()).first)}');

    await tester.pumpWidget(SecureShareApp(services: app));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('tab-send')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('choose-file')));
    await tester.pumpAndSettle();
    expect(find.text('from-phone.bin'), findsOneWidget);
    await tester.tap(find.byKey(const Key('send')));
    await tester.pump(const Duration(seconds: 1));
    expect(find.text(sendCode), findsOneWidget, reason: 'session code shown');
    // ignore: avoid_print
    print('E2E:CODE_SHOWN');
    await confirmCode(tester);
    // ignore: avoid_print
    print('E2E:TRANSFERRING');
    await waitFor(tester, (c) => c.phase == Phase.finished);
    expect(app.controller.outcome, Outcome.success, reason: app.controller.log.map((l) => l.key).join('\n'));
    await dir.delete(recursive: true);
  });
}
