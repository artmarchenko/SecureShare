// Every screen in every language on small screens and with large system
// fonts: any overflow ("RenderFlex overflowed") fails the test.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secureshare/app/i18n.dart';

import 'fakes.dart';
import 'screens.dart';

void main() {
  const configs = {
    'small phone 320x568': (Size(320, 568), 1.0),
    'phone, font 130%': (Size(392, 852), 1.3),
    'phone, font 200%': (Size(392, 852), 2.0),
    'small phone, font 150%': (Size(320, 568), 1.5),
  };
  for (final lang in languages) {
    for (final MapEntry(key: name, value: (size, scale)) in configs.entries) {
      testWidgets('$lang, $name: no overflow on any screen', (tester) async {
        final h = await pumpApp(tester, lang: lang, size: size, textScale: scale);
        final seen = <String>[];
        await walkScreens(tester, h, (screen) async {
          seen.add(screen);
          expect(tester.takeException(), isNull, reason: '$screen ($lang, $name)');
        });
        expect(seen, hasLength(15));
      });
    }
  }
  testWidgets('dark theme renders all screens', (tester) async {
    final h = await pumpApp(tester, themeMode: ThemeMode.dark);
    await walkScreens(tester, h, (_) async {});
  });
}
