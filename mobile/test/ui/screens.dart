// Walks the app through every screen and state, calling [shot] on each —
// used by the layout tests (overflow = failure) and by the screenshots.
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secureshare/app/device.dart';

import 'fakes.dart';

typedef Shot = Future<void> Function(String name);

Future<void> _pump(WidgetTester tester) async {
  for (var i = 0; i < 5; i++) {
    await tester.pump(const Duration(milliseconds: 100));
  }
}

Future<void> _tap(WidgetTester tester, Finder f) async {
  await tester.ensureVisible(f);
  await tester.tap(f);
  await tester.pumpAndSettle();
}

Future<void> walkScreens(WidgetTester tester, Harness h, Shot shot) async {
  final c = h.controller;

  // ── Send tab ──
  await shot('01-send-empty');
  h.device.nextPick = const PickedFile(handle: 2, name: 'disk-image.iso', size: 6 << 30);
  await _tap(tester, find.byKey(const Key('choose-file')));
  await shot('02-send-too-large');
  h.device.nextPick = longFile;
  await _tap(tester, find.byKey(const Key('change-file')));
  await shot('02-send-file');

  // ── Sending: session code, verification, progress, result ──
  await tester.tap(find.byKey(const Key('send')));
  await _pump(tester);
  final send = h.engine.last;
  send.status('relay_computing_hash', {'filename': c.fileName});
  send.status('relay_connecting_to');
  send.status('relay_waiting_receiver');
  await _pump(tester);
  await shot('03-send-code');
  send.status('relay_key_exchange');
  send.status('relay_protocol_info', {'our_proto': 2, 'peer_proto': 2, 'our_app': '1.0.0', 'peer_app': '4.0.0'});
  final answer = send.verify('K7PQ-2XMA');
  await _pump(tester);
  await shot('04-verify');
  c.confirmCode(true);
  await answer;
  send.status('relay_both_verified');
  send.status('relay_sending', {'filename': c.fileName, 'size': c.fileSize});
  send.progress(c.fileSize * 42 ~/ 100, c.fileSize, 6.5 * 1048576);
  await _pump(tester);
  await shot('05-send-progress');
  send.status('relay_connection_lost');
  send.status('relay_reconnecting', {'delay': 5, 'attempt': 1, 'max': 5});
  send.status('relay_retries_exhausted');
  send.finish(false);
  await _pump(tester);
  await shot('06-send-failed');
  await _tap(tester, find.byKey(const Key('done')));

  // ── Receive tab ──
  await _tap(tester, find.byKey(const Key('tab-receive')));
  await shot('07-receive-empty');
  await tester.enterText(find.byKey(const Key('code-input')), 'abc');
  await _tap(tester, find.byKey(const Key('receive')));
  await shot('08-receive-bad-code');
  await tester.enterText(find.byKey(const Key('code-input')), 'k7pq-2xma');
  await tester.tap(find.byKey(const Key('receive')));
  await _pump(tester);
  final recv = h.engine.last;
  const name = 'Звіт за третій квартал — фінальна версія (підписана).pdf';
  recv.status('relay_connecting_to');
  recv.status('relay_waiting_sender');
  recv.status('relay_receiving', {'filename': name, 'size': 48 * 1048576});
  recv.progress(48 * 1048576, 48 * 1048576);
  recv.status('relay_file_renamed', {'filename': 'Звіт за третій квартал — фінальна версія (підписана) (1).pdf'});
  recv.status('relay_saved', {'filename': name, 'speed': '6.1'});
  recv.finish(File('/storage/emulated/0/Download/SecureShare/$name'));
  await _pump(tester);
  await shot('09-receive-done');
  await _tap(tester, find.byKey(const Key('done')));

  // ── Menus ──
  await _tap(tester, find.byKey(const Key('help')));
  await shot('10-help');
  await tester.tap(find.byType(BackButton));
  await tester.pumpAndSettle();
  await _tap(tester, find.byKey(const Key('menu')));
  await _tap(tester, find.text(h.t('diag_title')));
  await shot('11-diagnostics');
  await tester.tap(find.byType(BackButton));
  await tester.pumpAndSettle();
  await _tap(tester, find.byKey(const Key('menu')));
  await _tap(tester, find.text(h.t('m_settings')));
  await shot('12-settings');
  await tester.tap(find.byType(BackButton));
  await tester.pumpAndSettle();
}

/// A long name: the worst case for the file card.
const longFile = PickedFile(
    handle: 3, name: 'Family archive 2019–2026 — photos, videos and scanned documents.7z', size: 4831838208);
