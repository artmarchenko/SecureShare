// Fakes for widget tests: a device that records what the app asked of
// Android, and a transfer engine the test drives step by step.
import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secureshare/app/controller.dart';
import 'package:secureshare/app/device.dart';
import 'package:secureshare/app/diagnostics.dart';
import 'package:secureshare/app/i18n.dart';
import 'package:secureshare/app/settings.dart';
import 'package:secureshare/app/updates.dart';
import 'package:secureshare/transfer/status.dart';
import 'package:secureshare/transfer/storage.dart';
import 'package:secureshare/ui/app.dart';

class FakeDevice implements Device {
  PickedFile? nextPick;
  PickedFile? shared;
  bool storageGranted = true;
  final released = <int>[];
  final services = <String>[]; // 'start: text', 'update: text', 'stop'
  final opened = <String>[];
  final sharedTexts = <String>[];
  final urls = <String>[];
  final _shared = StreamController<void>.broadcast();
  final _cancel = StreamController<void>.broadcast();
  Directory dir = Directory.systemTemp;

  void shareFile(PickedFile f) {
    shared = f;
    _shared.add(null);
  }

  void tapNotificationCancel() => _cancel.add(null);

  bool get serviceRunning => services.isNotEmpty && services.last != 'stop';

  @override
  Future<PickedFile?> pickFile() async => nextPick;
  @override
  Future<PickedFile?> takeSharedFile() async {
    final f = shared;
    shared = null;
    return f;
  }

  @override
  Future<void> releaseFile(int handle) async => released.add(handle);
  @override
  FileSource fileSource(PickedFile file) => _NullSource(file);
  @override
  Future<Directory> receiveDir() async => dir;
  @override
  Future<Directory> appDir() async => dir;
  @override
  Future<bool> ensureStoragePermission() async => storageGranted;
  @override
  Future<void> requestNotificationPermission() async {}
  @override
  Future<void> startService(ServiceStatus s) async => services.add('start: ${s.text}');
  @override
  Future<void> updateService(ServiceStatus s) async => services.add('update: ${s.title} | ${s.text}');
  @override
  Future<void> stopService() async => services.add('stop');
  @override
  Future<bool> openFile(String path) async {
    opened.add(path);
    return true;
  }

  @override
  Future<bool> shareText(String text) async {
    sharedTexts.add(text);
    return true;
  }

  @override
  Future<bool> openUrl(String url) async {
    urls.add(url);
    return true;
  }

  @override
  Stream<void> get sharedFileArrived => _shared.stream;
  @override
  Stream<void> get cancelRequested => _cancel.stream;
}

class _NullSource implements FileSource {
  _NullSource(this.f);
  final PickedFile f;
  @override
  String get name => f.name;
  @override
  Future<int> length() async => f.size;
  @override
  Future<List<int>> read(int offset, int length) async => const [];
  @override
  Future<String> sha256Hex() async => '';
  @override
  Future<void> close() async {}
}

/// One transfer the test drives: emit statuses, ask for verification, finish.
class FakeJob implements TransferJob {
  FakeJob(this.sending, this.code, this.cb);
  final bool sending;
  final String code;
  final EngineCallbacks cb;
  final _result = Completer<Object?>();
  bool cancelled = false;

  void status(String key, [Map<String, Object?> args = const {}]) {
    cb.onStatus(key, args);
    final s = stateForMessage[key];
    if (s != null) cb.onState(s);
  }

  void progress(int done, int total, [double speed = 2 * 1048576]) => cb.onProgress(done, total, speed);
  Future<bool> verify(String code) => cb.onVerify(code);
  void finish(Object? result) {
    if (!_result.isCompleted) _result.complete(result);
  }

  @override
  Future<Object?> run() => _result.future;

  @override
  void cancel() {
    cancelled = true;
    finish(sending ? false : null);
  }
}

class FakeEngine implements TransferEngine {
  final jobs = <FakeJob>[];
  FakeJob get last => jobs.last;

  @override
  TransferJob sender(String code, FileSource source, EngineCallbacks cb) => _add(FakeJob(true, code, cb));
  @override
  TransferJob receiver(String code, ReceiveFolder folder, EngineCallbacks cb) => _add(FakeJob(false, code, cb));

  FakeJob _add(FakeJob j) {
    jobs.add(j);
    return j;
  }
}

/// Diagnostics without network: every check passes.
Future<int> fakeDiagnostics(String relayUrl, Strings s, ReportRow report) async {
  for (final c in diagnosticChecks) {
    report(c, CheckResult(true, 'OK (12 ms)'));
  }
  return diagnosticChecks.length;
}

/// What the fake GitHub API returns (tests change it before checking).
String releasesJson = '[]';

class Harness {
  Harness(this.services, this.device, this.engine);
  final AppServices services;
  final FakeDevice device;
  final FakeEngine engine;
  TransferController get controller => services.controller;
  Strings get strings => services.strings;
  String t(String key, [Map<String, Object?> args = const {}]) => strings.t(key, args);
}

Future<Harness> makeHarness({String lang = 'en', Duration verifyTimeout = const Duration(seconds: 120)}) async =>
    harnessWith(await Strings.load(rootBundle, lang), verifyTimeout: verifyTimeout);

Harness harnessWith(Strings strings, {Duration verifyTimeout = const Duration(seconds: 120)}) {
  final device = FakeDevice();
  final engine = FakeEngine();
  final controller = TransferController(
    device: device,
    strings: strings,
    engine: engine,
    newCode: () => 'k7pq-2xma',
    verifyTimeout: verifyTimeout,
  );
  final services = AppServices(
    device: device,
    strings: strings,
    settings: Settings.memory(),
    controller: controller,
    updates: Updates(fetch: (_) async => releasesJson, current: '1.0.0'),
    diagnostics: fakeDiagnostics,
  );
  return Harness(services, device, engine);
}

/// Pumps the app on a phone-sized screen.
Future<Harness> pumpApp(
  WidgetTester tester, {
  String lang = 'en',
  Size size = const Size(400, 860),
  double textScale = 1.0,
  ThemeMode themeMode = ThemeMode.light,
  Duration verifyTimeout = const Duration(seconds: 120),
  Harness? harness,
  String? fontFamily,
  List<String>? fontFamilyFallback,
  Key? boundaryKey,
}) async {
  // large assets are decoded on another isolate: load them in real time, but
  // create the rest in the test's fake-async zone so stream callbacks run on pump()
  final h = harness ??
      harnessWith((await tester.runAsync(() => Strings.load(rootBundle, lang)))!, verifyTimeout: verifyTimeout);
  tester.view.physicalSize = size * 3;
  tester.view.devicePixelRatio = 3;
  tester.platformDispatcher.textScaleFactorTestValue = textScale;
  addTearDown(tester.view.reset);
  addTearDown(tester.platformDispatcher.clearAllTestValues);
  Widget app = SecureShareApp(
    services: h.services,
    themeMode: themeMode,
    fontFamily: fontFamily,
    fontFamilyFallback: fontFamilyFallback,
  );
  if (boundaryKey != null) app = RepaintBoundary(key: boundaryKey, child: app);
  await tester.pumpWidget(app);
  await tester.pumpAndSettle();
  return h;
}

const sampleFile = PickedFile(handle: 7, name: 'Holiday photos 2026.zip', size: 734003200);
