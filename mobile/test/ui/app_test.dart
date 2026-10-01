// Widget tests of the app's screens with a scripted transfer engine.
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secureshare/app/controller.dart';
import 'package:secureshare/app/device.dart';
import 'package:secureshare/app/i18n.dart';

import 'fakes.dart';

/// Lets the indeterminate progress bar run without pumpAndSettle hanging.
Future<void> settle(WidgetTester tester) async {
  for (var i = 0; i < 5; i++) {
    await tester.pump(const Duration(milliseconds: 100));
  }
}

Future<void> tapKey(WidgetTester tester, String key) async {
  final f = find.byKey(Key(key));
  await tester.ensureVisible(f);
  await tester.tap(f);
  await settle(tester);
}

/// The AppBar back button (pageBack() looks it up by its English tooltip).
Future<void> back(WidgetTester tester) async {
  await tester.tap(find.byType(BackButton));
  await tester.pumpAndSettle();
}

/// A line in the transfer log (time + text in one rich text).
Finder logLine(String text) => find.textContaining(text, findRichText: true);

Future<void> enterCode(WidgetTester tester, String text) async {
  await tapKey(tester, 'tab-receive');
  await tester.enterText(find.byKey(const Key('code-input')), text);
  await tapKey(tester, 'receive');
}

void main() {
  group('send', () {
    testWidgets('pick → code → verify → progress → done', (tester) async {
      final h = await pumpApp(tester);
      expect(tester.widget<FilledButton>(find.byKey(const Key('send'))).onPressed, isNull,
          reason: 'nothing to send yet');

      h.device.nextPick = sampleFile;
      await tapKey(tester, 'choose-file');
      expect(find.text('Holiday photos 2026.zip'), findsOneWidget);
      expect(find.text('700.0 MB'), findsOneWidget);

      await tapKey(tester, 'send');
      final job = h.engine.last;
      expect(job.sending, isTrue);
      expect(job.code, 'k7pq-2xma');
      expect(h.device.serviceRunning, isTrue);

      job.status('relay_connecting_to');
      job.status('relay_waiting_receiver');
      await settle(tester);
      // the session code to give to the receiver
      expect(find.byKey(const Key('session-code')), findsOneWidget);
      expect(find.text('k7pq-2xma'), findsOneWidget);
      await tapKey(tester, 'share-code');
      expect(h.device.sharedTexts.single, contains('k7pq-2xma'));

      job.status('relay_key_exchange');
      final answer = job.verify('YYYX-YN3F');
      await settle(tester);
      expect(find.byKey(const Key('session-code')), findsNothing);
      expect(find.text('YYYX-YN3F'), findsOneWidget);
      expect(h.device.services.last, contains(h.t('m_notif_verify')));
      await tapKey(tester, 'codes-match');
      expect(await answer, isTrue);
      expect(find.byKey(const Key('verify')), findsNothing);

      job.status('relay_sending', {'filename': sampleFile.name, 'size': sampleFile.size});
      job.progress(sampleFile.size ~/ 4, sampleFile.size);
      await settle(tester);
      expect(find.text(h.t('state_transferring')), findsOneWidget);
      expect(tester.widget<LinearProgressIndicator>(find.byKey(const Key('progress'))).value, closeTo(0.25, 0.001));
      expect(find.textContaining('175.0 MB / 700.0 MB'), findsOneWidget);
      expect(find.textContaining('2.0 MB/s'), findsOneWidget);
      expect(find.textContaining('left'), findsOneWidget);
      expect(h.device.services.last, contains('25%'));

      job.status('relay_file_sent_ok');
      job.finish(true);
      await settle(tester);
      expect(find.text(h.t('m_result_sent')), findsOneWidget);
      expect(tester.widget<LinearProgressIndicator>(find.byKey(const Key('progress'))).value, 1);
      expect(h.device.services.last, 'stop');
      expect(h.device.released, [sampleFile.handle], reason: 'file released after a successful send');

      await tapKey(tester, 'done');
      expect(find.byKey(const Key('choose-file')), findsOneWidget);
    });

    testWidgets('codes differ → transfer stops, file stays selected for a retry', (tester) async {
      final h = await pumpApp(tester);
      h.device.nextPick = sampleFile;
      await tapKey(tester, 'choose-file');
      await tapKey(tester, 'send');
      final answer = h.engine.last.verify('AAAA-BBBB');
      await settle(tester);
      await tapKey(tester, 'codes-differ');
      expect(await answer, isFalse);
      h.engine.last.status('relay_verify_rejected');
      h.engine.last.finish(false);
      await settle(tester);
      expect(find.text(h.t('m_result_failed')), findsOneWidget);
      expect(h.device.released, isEmpty);
      await tapKey(tester, 'done');
      expect(find.text(sampleFile.name), findsOneWidget);
    });

    testWidgets('cancel mid-transfer shows how to resume', (tester) async {
      final h = await pumpApp(tester);
      h.device.nextPick = sampleFile;
      await tapKey(tester, 'choose-file');
      await tapKey(tester, 'send');
      final job = h.engine.last;
      job.status('relay_sending', {'filename': sampleFile.name, 'size': sampleFile.size});
      job.progress(1000, sampleFile.size);
      await settle(tester);
      await tapKey(tester, 'cancel');
      expect(job.cancelled, isTrue);
      expect(find.text(h.t('m_result_cancelled')), findsOneWidget);
      expect(find.text(h.t('m_resume_hint_send')), findsOneWidget);
      expect(logLine(h.t('transfer_cancelled_user')), findsOneWidget);
      expect(h.device.services.last, 'stop');
    });

    testWidgets('Cancel in the notification cancels the transfer', (tester) async {
      final h = await pumpApp(tester);
      h.device.nextPick = sampleFile;
      await tapKey(tester, 'choose-file');
      await tapKey(tester, 'send');
      h.device.tapNotificationCancel();
      await settle(tester);
      expect(h.engine.last.cancelled, isTrue);
      expect(find.text(h.t('m_result_cancelled')), findsOneWidget);
    });

    testWidgets('verification times out like on the desktop', (tester) async {
      final h = await pumpApp(tester, verifyTimeout: const Duration(seconds: 5));
      h.device.nextPick = sampleFile;
      await tapKey(tester, 'choose-file');
      await tapKey(tester, 'send');
      final answer = h.engine.last.verify('AAAA-BBBB');
      await tester.pump(const Duration(seconds: 6));
      expect(await answer, isFalse);
      await settle(tester);
      expect(find.byKey(const Key('verify')), findsNothing);
      expect(logLine(h.t('verify_timeout')), findsOneWidget);
    });

    testWidgets('a file shared from another app opens the Send tab', (tester) async {
      final h = await pumpApp(tester);
      await tapKey(tester, 'tab-receive');
      h.device.shareFile(sampleFile);
      await settle(tester);
      expect(find.text(sampleFile.name), findsOneWidget);
      expect(find.byKey(const Key('send')), findsOneWidget);
    });

    testWidgets('files over the 5 GB limit cannot be sent', (tester) async {
      final h = await pumpApp(tester);
      h.device.nextPick = const PickedFile(handle: 1, name: 'huge.iso', size: 6 * 1024 * 1024 * 1024);
      await tapKey(tester, 'choose-file');
      expect(find.textContaining('5.0 GB'), findsOneWidget);
      expect(tester.widget<FilledButton>(find.byKey(const Key('send'))).onPressed, isNull);
    });
  });

  group('receive', () {
    testWidgets('code is normalised; received file can be opened', (tester) async {
      final h = await pumpApp(tester);
      await enterCode(tester, ' K7PQ 2XMA ');
      final job = h.engine.last;
      expect(job.sending, isFalse);
      expect(job.code, 'k7pq-2xma');

      job.status('relay_receiving', {'filename': 'report.pdf', 'size': 3 * 1048576});
      job.progress(1048576, 3 * 1048576);
      await settle(tester);
      expect(find.byKey(const Key('file-name')), findsOneWidget);
      expect(find.text('report.pdf'), findsOneWidget);
      expect(h.device.services.last, contains('report.pdf'));

      final saved = File('${h.device.dir.path}/report.pdf');
      job.finish(saved);
      await settle(tester);
      expect(find.text(h.t('m_result_received')), findsOneWidget);
      expect(find.text(saved.path), findsOneWidget);
      await tapKey(tester, 'open-file');
      expect(h.device.opened, [saved.path]);
    });

    testWidgets('invalid code is explained, nothing starts', (tester) async {
      final h = await pumpApp(tester);
      await enterCode(tester, 'abc');
      expect(find.text(h.t('m_invalid_code')), findsOneWidget);
      expect(h.engine.jobs, isEmpty);
    });

    testWidgets('paste takes the code out of a shared message', (tester) async {
      final h = await pumpApp(tester);
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
        if (call.method == 'Clipboard.getData') return {'text': 'SecureShare code: ab12-cd34'};
        return null;
      });
      addTearDown(() => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, null));
      await tapKey(tester, 'tab-receive');
      await tapKey(tester, 'paste');
      await tapKey(tester, 'receive');
      expect(h.engine.last.code, 'ab12-cd34');
    });

    testWidgets('no storage permission → explained, nothing starts', (tester) async {
      final h = await pumpApp(tester);
      h.device.storageGranted = false;
      await enterCode(tester, 'abcd-1234');
      expect(find.text(h.t('m_storage_denied')), findsOneWidget);
      expect(h.engine.jobs, isEmpty);
    });

    testWidgets('a failed reconnect attempt is not shown as the final error', (tester) async {
      final h = await pumpApp(tester);
      await enterCode(tester, 'abcd-1234');
      final job = h.engine.last;
      job.status('relay_receiving', {'filename': 'a.bin', 'size': 1 << 20});
      job.status('relay_connection_lost');
      job.status('relay_connect_error', {'error': 'refused'});
      await settle(tester);
      expect(find.text(h.t('state_error')), findsNothing);
      expect(find.text(h.t('state_connecting')), findsOneWidget);

      job.status('relay_file_renamed', {'filename': 'a (1).bin'});
      job.finish(File('${h.device.dir.path}/a (1).bin'));
      await settle(tester);
      expect(find.byKey(const Key('file-name')).evaluate().single.widget, isA<Text>().having((t) => t.data, 'name', 'a (1).bin'));
    });

    testWidgets('interrupted receive explains how to resume', (tester) async {
      final h = await pumpApp(tester);
      await enterCode(tester, 'abcd-1234');
      final job = h.engine.last;
      job.status('relay_receiving', {'filename': 'big.iso', 'size': 1 << 30});
      job.progress(1 << 28, 1 << 30);
      job.status('relay_connection_lost');
      job.status('relay_retries_exhausted');
      job.status('relay_progress_saved', {'received': 512, 'total': 2048});
      job.finish(null);
      await settle(tester);
      expect(find.text(h.t('m_result_failed')), findsOneWidget);
      expect(find.text(h.t('m_resume_hint_receive')), findsOneWidget);
      expect(logLine(h.t('relay_progress_saved', {'received': 512, 'total': 2048})), findsOneWidget);
    });
  });

  group('menus', () {
    testWidgets('language switch applies at once and is kept', (tester) async {
      final h = await pumpApp(tester);
      await tapKey(tester, 'menu');
      await tester.tap(find.text(h.t('m_settings')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('lang-uk')));
      await tester.pumpAndSettle();
      expect(h.services.settings.language, 'uk');
      expect(find.text('Налаштування'), findsOneWidget);
      await back(tester);
      expect(find.text('Вибрати файл'), findsOneWidget);

      await tapKey(tester, 'menu');
      await tester.tap(find.text('Налаштування'));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('lang-de')));
      await tester.pumpAndSettle();
      await back(tester);
      expect(find.text('Datei auswählen'), findsOneWidget);
    });

    testWidgets('diagnostics, help and links', (tester) async {
      final h = await pumpApp(tester);
      await tapKey(tester, 'menu');
      await tester.tap(find.text(h.t('diag_title')));
      await tester.pumpAndSettle();
      expect(find.text(h.t('diag_all_ok', {'passed': 5, 'total': 5})), findsOneWidget);
      await back(tester);

      await tapKey(tester, 'help');
      await tester.pumpAndSettle();
      expect(find.text(h.t('help_verify_title')), findsOneWidget);
      await back(tester);

      await tapKey(tester, 'menu');
      await tester.tap(find.text(h.t('m_settings')));
      await tester.pumpAndSettle();
      await tester.tap(find.text(h.t('m_source_code')));
      expect(h.device.urls.single, contains('github.com'));
    });
  });

  group('helpers', () {
    test('session codes look like the desktop ones', () {
      for (var i = 0; i < 100; i++) {
        expect(newSessionCode(), matches(RegExp(r'^[a-z0-9]{4}-[a-z0-9]{4}$')));
      }
      expect(normalizeCode('ABCD1234'), 'abcd-1234');
      expect(normalizeCode(' ab cd-12 34 '), 'abcd-1234');
      expect(normalizeCode('abcd-123'), isNull);
      expect(normalizeCode('abcd_1234'), isNull);
    });

    testWidgets('formatting matches app/format.py', (tester) async {
      final h = await tester.runAsync(() => makeHarness()) as Harness;
      final s = h.strings;
      expect(s.size(512), '512.0 B');
      expect(s.size(1536), '1.5 KB');
      expect(s.size(5 * 1024 * 1024 * 1024), '5.0 GB');
      expect(s.eta(3725), '1h 02m');
      expect(s.eta(65), '1m 05s');
      expect(s.eta(9), '9s');
      expect(s.t('relay_sending', {'filename': 'a.bin', 'size': 2048}), contains('a.bin (2.0 KB)'));
      expect(unwrap('one\ntwo\n•  three\n1.  four'), 'one two\n•  three\n1.  four');
      expect(unwrap('schützt vor\nMan-in-the-Middle'), 'schützt vor Man-in-the-Middle');
      expect(unwrap('Absatz.\n\nNeuer Absatz\n✅ Liste'), 'Absatz.\n\nNeuer Absatz\n✅ Liste');
      expect(unwrap('Daten —\n   er sieht'), 'Daten — er sieht');
      expect(plain('✅ Codes match'), 'Codes match');
      expect(plain('⏹ Cancel'), 'Cancel');
    });
  });
}
