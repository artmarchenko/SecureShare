// Invitation links: parsing, the app's reaction, and that the website side
// (assetlinks.json, /r page) matches the app.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secureshare/app/invite.dart';

import 'ui/fakes.dart';

Future<void> settle(WidgetTester tester) async {
  for (var i = 0; i < 5; i++) {
    await tester.pump(const Duration(milliseconds: 100));
  }
}

String fieldText(WidgetTester tester) => tester.widget<TextField>(find.byKey(const Key('code-input'))).controller!.text;

void main() {
  group('codeFromInvite', () {
    test('accepts our links, code after # (or ?c= from the /r page)', () {
      expect(inviteLink('k7pq-2xma'), 'https://secureshare-relay.duckdns.org/r#k7pq-2xma');
      expect(codeFromInvite('https://secureshare-relay.duckdns.org/r#k7pq-2xma'), 'k7pq-2xma');
      expect(codeFromInvite('https://secureshare-relay.duckdns.org/r#K7PQ2XMA'), 'k7pq-2xma');
      expect(codeFromInvite(' https://secureshare-relay.duckdns.org/r/#k7pq%202xma '), 'k7pq-2xma');
      expect(codeFromInvite('https://secureshare-relay.duckdns.org/r?c=ab12-cd34'), 'ab12-cd34');
    });

    test('rejects anything else', () {
      for (final bad in [
        'http://secureshare-relay.duckdns.org/r#k7pq-2xma', // not https
        'https://evil.example/r#k7pq-2xma',
        'https://secureshare-relay.duckdns.org.evil.example/r#k7pq-2xma',
        'https://secureshare-relay.duckdns.org/robots.txt#k7pq-2xma',
        'https://secureshare-relay.duckdns.org/r#k7pq-2xm',
        'https://secureshare-relay.duckdns.org/r#<script>',
        'https://secureshare-relay.duckdns.org/r',
        'not a link',
      ]) {
        expect(codeFromInvite(bad), isNull, reason: bad);
      }
    });
  });

  group('in the app', () {
    testWidgets('a link opens Receive with the code filled in; nothing starts by itself', (tester) async {
      final h = await pumpApp(tester);
      expect(find.byKey(const Key('choose-file')), findsOneWidget, reason: 'starts on Send');
      h.device.openLink('https://secureshare-relay.duckdns.org/r#K7PQ-2XMA');
      await settle(tester);
      expect(fieldText(tester), 'k7pq-2xma');
      expect(find.byKey(const Key('invite-hint')), findsOneWidget);
      expect(h.engine.jobs, isEmpty);

      await tester.tap(find.byKey(const Key('receive')));
      await settle(tester);
      expect(h.engine.last.code, 'k7pq-2xma');
    });

    testWidgets('editing the code hides the invitation hint', (tester) async {
      final h = await pumpApp(tester);
      h.device.openLink(inviteLink('ab12-cd34'));
      await settle(tester);
      await tester.enterText(find.byKey(const Key('code-input')), 'zzzz-0000');
      await settle(tester);
      expect(find.byKey(const Key('invite-hint')), findsNothing);
    });

    testWidgets('a bad link is explained', (tester) async {
      final h = await pumpApp(tester);
      h.device.openLink('https://secureshare-relay.duckdns.org/r#nope');
      await settle(tester);
      expect(find.text(h.t('m_invite_invalid')), findsOneWidget);
    });

    testWidgets('during a transfer the link does not replace it', (tester) async {
      final h = await pumpApp(tester);
      h.device.nextPick = sampleFile;
      await tester.tap(find.byKey(const Key('choose-file')));
      await settle(tester);
      await tester.tap(find.byKey(const Key('send')));
      await settle(tester);
      h.device.openLink(inviteLink('ab12-cd34'));
      await settle(tester);
      expect(find.text(h.t('m_invite_busy')), findsOneWidget);
      expect(find.byKey(const Key('cancel')), findsOneWidget, reason: 'still on the transfer');
    });

    testWidgets('Share on the session code sends a link and the code', (tester) async {
      final h = await pumpApp(tester);
      h.device.nextPick = sampleFile;
      await tester.tap(find.byKey(const Key('choose-file')));
      await settle(tester);
      await tester.tap(find.byKey(const Key('send')));
      await settle(tester);
      h.engine.last.status('relay_waiting_receiver');
      await settle(tester);
      await tester.tap(find.byKey(const Key('share-code')));
      final text = h.device.sharedTexts.single;
      expect(text, contains('https://secureshare-relay.duckdns.org/r#k7pq-2xma'));
      expect(text.replaceAll(inviteLink('k7pq-2xma'), ''), contains('k7pq-2xma'), reason: 'code also for the PC');
    });

    testWidgets('pasting a whole shared message takes the code', (tester) async {
      final h = await pumpApp(tester);
      final message = h.t('m_share_code_text', {'code': 'ab12-cd34', 'link': inviteLink('ab12-cd34')});
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
        if (call.method == 'Clipboard.getData') return {'text': message};
        return null;
      });
      addTearDown(() => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, null));
      await tester.tap(find.byKey(const Key('tab-receive')));
      await settle(tester);
      await tester.tap(find.byKey(const Key('paste')));
      await settle(tester);
      expect(fieldText(tester), 'ab12-cd34');
    });
  });

  group('website side', () {
    test('assetlinks.json names this app and the pinned release certificate', () {
      final links = jsonDecode(File('../server/www/assetlinks.json').readAsStringSync()) as List;
      final target = links.single['target'] as Map<String, dynamic>;
      expect(target['package_name'], 'io.github.artmarchenko.secureshare');
      final pinned = File('android/release-cert.sha256').readAsStringSync().trim();
      final fp = (target['sha256_cert_fingerprints'] as List).single as String;
      expect(fp.replaceAll(':', '').toLowerCase(), pinned);
    });

    test('the manifest handles exactly the /r link of this host', () {
      final manifest = File('android/app/src/main/AndroidManifest.xml').readAsStringSync();
      expect(manifest, contains('android:host="$inviteHost" android:path="$invitePath"'));
      expect(manifest, contains('android:autoVerify="true"'));
      expect(manifest, contains('flutter_deeplinking_enabled" android:value="false"'), reason: 'else Flutter pushes /r as a route');
    });

    test('the /r page loads nothing from elsewhere and never sends the code', () {
      final html = File('../server/www/r.html').readAsStringSync();
      final js = File('../server/www/r.js').readAsStringSync();
      expect(RegExp(r'(src|href)="https?://').hasMatch(html), isFalse);
      for (final call in ['fetch(', 'XMLHttpRequest', 'sendBeacon', 'innerHTML', 'document.write']) {
        expect(js.contains(call), isFalse, reason: call);
      }
      expect(js, contains('package=io.github.artmarchenko.secureshare'));
    });
  });
}
