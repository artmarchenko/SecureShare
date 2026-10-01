// Update check: only android-v* releases count, the newest one wins.
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secureshare/app/updates.dart';

import 'ui/fakes.dart';

Map<String, Object?> release(String tag, {bool draft = false, bool pre = false, bool apk = true, String body = ''}) => {
      'tag_name': tag,
      'draft': draft,
      'prerelease': pre,
      'html_url': 'https://github.com/artmarchenko/SecureShare/releases/tag/$tag',
      'body': body,
      'assets': [
        if (apk) {'name': 'SecureShare.apk', 'browser_download_url': 'https://example.test/$tag/SecureShare.apk'},
        {'name': 'SHA256SUMS.txt', 'browser_download_url': 'https://example.test/$tag/SHA256SUMS.txt'},
      ],
    };

String releases(List<Map<String, Object?>> list) => jsonEncode(list);

void main() {
  group('newestAndroidRelease', () {
    test('ignores desktop releases, drafts, prereleases and releases without an APK', () {
      final r = newestAndroidRelease(releases([
        release('v4.9.0'),
        release('android-v1.3.0', draft: true),
        release('android-v1.2.0', pre: true),
        release('android-v1.1.5', apk: false),
        release('android-v1.1.0', body: '## SecureShare\n\n### Changes\n- **Faster** resume\n- Fix\n\n### Download\nx'),
        release('android-v1.0.0'),
        release('android-v1.0.10'),
      ]))!;
      expect(r.version, '1.1.0');
      expect(r.apkUrl, 'https://example.test/android-v1.1.0/SecureShare.apk');
      expect(r.notes, '- Faster resume\n- Fix');
    });

    test('numeric, not string, comparison', () {
      expect(newestAndroidRelease(releases([release('android-v1.9.0'), release('android-v1.10.0')]))!.version, '1.10.0');
      expect(compareVersions(parseVersion('1.0.10')!, parseVersion('1.0.9')!), greaterThan(0));
      expect(parseVersion('android-v1.2'), isNull);
      expect(newestAndroidRelease('{"message": "rate limited"}'), isNull);
    });
  });

  group('Updates.check', () {
    test('newer → available, same → up to date, error → failed', () async {
      var json = releases([release('android-v1.0.1')]);
      final u = Updates(fetch: (_) async => json, current: '1.0.0');
      await u.check();
      expect(u.status, UpdateStatus.available);
      expect(u.release!.version, '1.0.1');

      json = releases([release('android-v1.0.0')]);
      await u.check();
      expect(u.status, UpdateStatus.upToDate);
      expect(u.release, isNull);

      final failing = Updates(fetch: (_) async => throw Exception('offline'), current: '1.0.0');
      await failing.check();
      expect(failing.status, UpdateStatus.failed);
    });
  });

  testWidgets('banner → details → Download opens the release APK; Later hides it', (tester) async {
    releasesJson = releases([release('android-v1.2.0', body: '### Changes\n- New things')]);
    addTearDown(() => releasesJson = '[]');
    final h = await pumpApp(tester);
    await h.services.updates.check();
    await tester.pumpAndSettle();
    expect(find.text(h.t('m_update_available', {'version': '1.2.0'})), findsOneWidget);

    await tester.tap(find.byKey(const Key('update-details')));
    await tester.pumpAndSettle();
    expect(find.text('- New things'), findsOneWidget);
    await tester.tap(find.byKey(const Key('update-download')));
    await tester.pumpAndSettle();
    expect(h.device.urls.single, 'https://example.test/android-v1.2.0/SecureShare.apk');

    await tester.tap(find.text(h.t('m_update_later')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('update-banner')), findsNothing);
  });

  testWidgets('settings: check for updates → up to date', (tester) async {
    releasesJson = releases([release('android-v1.0.0')]);
    addTearDown(() => releasesJson = '[]');
    final h = await pumpApp(tester);
    await tester.tap(find.byKey(const Key('menu')));
    await tester.pumpAndSettle();
    await tester.tap(find.text(h.t('m_settings')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('update-check')));
    await tester.pumpAndSettle();
    expect(find.textContaining('1.0.0'), findsWidgets);
    expect(h.services.updates.status, UpdateStatus.upToDate);
  });
}
