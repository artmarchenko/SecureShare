/// App root: theme, shared services for the screens, language.
library;

import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

import '../app/controller.dart';
import '../app/device.dart';
import '../app/diagnostics.dart';
import '../app/i18n.dart';
import '../app/settings.dart';
import 'home_page.dart';

/// Everything the screens need, created once in main() (or by a test).
class AppServices {
  AppServices({
    required this.device,
    required this.strings,
    required this.settings,
    required this.controller,
    this.relayUrl = 'wss://secureshare-relay.duckdns.org',
    this.diagnostics = runDiagnostics,
  });

  final Device device;
  final Strings strings;
  final Settings settings;
  final TransferController controller;
  final String relayUrl;
  final Future<int> Function(String relayUrl, Strings s, ReportRow report) diagnostics;
}

class AppScope extends InheritedWidget {
  const AppScope({super.key, required this.services, required super.child});
  final AppServices services;

  static AppServices of(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<AppScope>()!.services;

  @override
  bool updateShouldNotify(AppScope oldWidget) => services != oldWidget.services;
}

const seedColor = Color(0xFF1F6AA5); // the desktop app's blue

ThemeData appTheme(Brightness brightness, {String? fontFamily, List<String>? fontFamilyFallback}) => ThemeData(
      colorScheme: ColorScheme.fromSeed(seedColor: seedColor, brightness: brightness),
      useMaterial3: true,
      fontFamily: fontFamily,
      fontFamilyFallback: fontFamilyFallback,
    );

class SecureShareApp extends StatelessWidget {
  const SecureShareApp({
    super.key,
    required this.services,
    this.themeMode = ThemeMode.system,
    this.fontFamily,
    this.fontFamilyFallback,
  });

  final AppServices services;
  final ThemeMode themeMode;
  final String? fontFamily; // screenshots in tests load real fonts
  final List<String>? fontFamilyFallback;

  @override
  Widget build(BuildContext context) {
    return AppScope(
      services: services,
      child: ListenableBuilder(
        listenable: services.strings,
        builder: (context, _) => MaterialApp(
          title: 'SecureShare',
          debugShowCheckedModeBanner: false,
          theme: appTheme(Brightness.light, fontFamily: fontFamily, fontFamilyFallback: fontFamilyFallback),
          darkTheme: appTheme(Brightness.dark, fontFamily: fontFamily, fontFamilyFallback: fontFamilyFallback),
          themeMode: themeMode,
          locale: Locale(services.strings.lang),
          supportedLocales: [for (final l in languages) Locale(l)],
          localizationsDelegates: GlobalMaterialLocalizations.delegates,
          home: const HomePage(),
        ),
      ),
    );
  }
}
