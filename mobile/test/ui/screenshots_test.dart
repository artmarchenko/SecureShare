// Renders every screen (3 languages × light/dark) to build/screenshots/ for
// a visual review — uploaded as a CI artifact. Run on its own:
//   flutter test --tags screenshots
@Tags(['screenshots'])
library;

import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:secureshare/app/i18n.dart';

import 'fakes.dart';
import 'screens.dart';

/// Loads the first existing file of each weight in [candidates]; false if none.
Future<bool> _loadFont(String family, List<List<String>> candidates) async {
  final loader = FontLoader(family);
  var any = false;
  for (final paths in candidates) {
    for (final path in paths) {
      final f = File(path);
      if (f.existsSync()) {
        loader.addFont(f.readAsBytes().then(ByteData.sublistView));
        any = true;
        break;
      }
    }
  }
  if (any) await loader.load();
  return any;
}

void main() {
  // Flutter's own copy (…/bin/cache/artifacts/material_fonts, next to the test
  // runner), else the system one (Linux CI: apt install fonts-roboto)
  final flutterFonts = p.join(p.dirname(p.dirname(p.dirname(Platform.resolvedExecutable))), 'material_fonts');
  List<String> roboto(String weight, String file) => [
        p.join(flutterFonts, 'roboto-$weight.ttf'),
        '/usr/share/fonts/truetype/roboto/unhinted/RobotoTTF/Roboto-$file.ttf',
        '/usr/share/fonts/truetype/roboto/hinted/Roboto-$file.ttf',
      ];

  setUpAll(() async {
    if (!await _loadFont('Roboto', [roboto('regular', 'Regular'), roboto('medium', 'Medium'), roboto('bold', 'Bold')])) {
      throw StateError('Roboto not found (Flutter material_fonts or apt fonts-roboto)');
    }
    // the icon font every Flutter test bundle carries (uses-material-design)
    final icons = FontLoader('MaterialIcons')..addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'));
    await icons.load();
    // emoji in status texts: whatever the machine has
    await _loadFont('Emoji', [
      ['/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf', r'C:\Windows\Fonts\seguiemj.ttf'],
    ]);
    // CodeText asks for the platform's 'monospace'
    await _loadFont('monospace', [
      ['/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf', r'C:\Windows\Fonts\consola.ttf'],
    ]);
  });

  for (final lang in languages) {
    for (final dark in [false, true]) {
      final theme = dark ? 'dark' : 'light';
      testWidgets('screenshots $lang $theme', (tester) async {
        debugDisableShadows = false; // real shadows, not the test outlines
        try {
          const key = Key('screen');
          final h = await pumpApp(
            tester,
            lang: lang,
            size: const Size(392, 852),
            themeMode: dark ? ThemeMode.dark : ThemeMode.light,
            fontFamily: 'Roboto',
            fontFamilyFallback: const ['Emoji'],
            boundaryKey: key,
          );
          final dir = Directory(p.join('build', 'screenshots', '$lang-$theme'))..createSync(recursive: true);
          await walkScreens(tester, h, (name) async {
            final boundary = tester.renderObject<RenderRepaintBoundary>(find.byKey(key));
            await tester.runAsync(() async {
              final image = await boundary.toImage(pixelRatio: 2);
              final png = await image.toByteData(format: ui.ImageByteFormat.png);
              await File(p.join(dir.path, '$name.png')).writeAsBytes(png!.buffer.asUint8List());
            });
          });
        } finally {
          debugDisableShadows = true;
        }
      });
    }
  }
}
