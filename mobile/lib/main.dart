import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'app/controller.dart';
import 'app/device.dart';
import 'app/i18n.dart';
import 'app/selftest.dart';
import 'app/settings.dart';
import 'app/updates.dart';
import 'transfer/peer.dart';
import 'ui/app.dart';

/// `--dart-define=RELAY_URL=ws://10.0.2.2:8765` points a test build at a
/// local relay (10.0.2.2 is the host machine as seen from the emulator).
const relayUrl = String.fromEnvironment('RELAY_URL', defaultValue: 'wss://secureshare-relay.duckdns.org');

Future<AppServices> createServices({Device? device, TransferEngine? engine, String Function()? newCode}) async {
  final d = device ?? NativeDevice();
  final settings = await Settings.load(await d.appDir());
  final lang = settings.language ??
      languageForLocale(WidgetsBinding.instance.platformDispatcher.locale.languageCode);
  final strings = await Strings.load(rootBundle, lang);
  final controller = TransferController(
    device: d,
    strings: strings,
    engine: engine ?? const RelayEngine(TransferOptions(relayUrl: relayUrl)),
    newCode: newCode,
  );
  return AppServices(
      device: d, strings: strings, settings: settings, controller: controller, updates: Updates(), relayUrl: relayUrl);
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final services = await createServices();
  runApp(SecureShareApp(services: services));
  final device = services.device;
  if (device is NativeDevice) {
    device.selfTestRequested.listen((_) => reportSelfTest(device, services.strings));
    if (await device.takeSelfTest()) unawaited(reportSelfTest(device, services.strings));
  }
  unawaited(services.updates.check()); // newer android-v* release on GitHub?
  await services.controller.takeSharedFile(); // opened via "Share → SecureShare"
}
