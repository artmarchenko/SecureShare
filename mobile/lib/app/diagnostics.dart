/// Network checks — same steps and texts as app/diagnostics.py.
library;

import 'dart:async';
import 'dart:io';

import 'i18n.dart';

const diagnosticChecks = ['internet', 'dns', 'tls', 'websocket', 'latency'];

enum CheckLevel { ok, warn, bad, skipped }

class CheckResult {
  const CheckResult(this.ok, this.detail, [this.level]);
  final bool ok;
  final String detail;
  final CheckLevel? level; // null = from [ok]
}

typedef ReportRow = void Function(String check, CheckResult result);

/// Runs all checks against [relayUrl]; returns how many passed.
Future<int> runDiagnostics(String relayUrl, Strings s, ReportRow report,
    {Duration timeout = const Duration(seconds: 5)}) async {
  final uri = Uri.parse(relayUrl);
  final host = uri.host;
  final port = uri.hasPort ? uri.port : 443;
  var passed = 0;

  void skipRest(String after, String reasonKey) {
    for (final c in diagnosticChecks.skip(diagnosticChecks.indexOf(after) + 1)) {
      report(c, CheckResult(false, s.t(reasonKey), CheckLevel.skipped));
    }
  }

  // 1. Internet (TCP 443 is rarely blocked, unlike outbound port 53)
  try {
    (await Socket.connect('1.1.1.1', 443, timeout: timeout)).destroy();
    report('internet', CheckResult(true, s.t('diag_connected')));
    passed++;
  } catch (_) {
    report('internet', CheckResult(false, s.t('diag_no_connection')));
    skipRest('internet', 'diag_skipped_no_internet');
    return passed;
  }

  // 2. DNS
  try {
    final sw = Stopwatch()..start();
    final addresses = await InternetAddress.lookup(host).timeout(timeout);
    report('dns', CheckResult(true, '${addresses.first.address} (${sw.elapsedMilliseconds} ms)'));
    passed++;
  } catch (_) {
    report('dns', CheckResult(false, s.t('diag_dns_fail', {'host': host})));
    skipRest('dns', 'diag_skipped_dns_error');
    return passed;
  }

  // 3. TLS certificate
  try {
    final socket = await SecureSocket.connect(host, port, timeout: timeout);
    final cert = socket.peerCertificate;
    socket.destroy();
    final issuer = RegExp(r'O=([^,/]+)').firstMatch(cert?.issuer ?? '')?.group(1) ?? 'Unknown';
    final until = cert?.endValidity.toIso8601String().substring(0, 10) ?? '?';
    report('tls', CheckResult(true, '$issuer ($until)'));
    passed++;
  } on HandshakeException {
    report('tls', CheckResult(false, s.t('diag_tls_invalid')));
  } catch (e) {
    report('tls', CheckResult(false, s.t('diag_tls_error', {'error': e.runtimeType})));
  }

  // 4. WebSocket — what transfers use
  try {
    final sw = Stopwatch()..start();
    final ws = await WebSocket.connect(relayUrl).timeout(timeout);
    final ms = sw.elapsedMilliseconds;
    unawaited(ws.close());
    report('websocket', CheckResult(true, 'OK ($ms ms)'));
    passed++;
  } catch (_) {
    report('websocket', CheckResult(false, s.t('diag_ws_fail')));
  }

  // 5. Latency: median of 3 TCP connects
  try {
    final pings = <int>[];
    for (var i = 0; i < 3; i++) {
      final sw = Stopwatch()..start();
      (await Socket.connect(host, port, timeout: timeout)).destroy();
      pings.add(sw.elapsedMilliseconds);
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    pings.sort();
    final median = pings[1];
    final (quality, level) = median < 100
        ? (s.t('diag_quality_excellent'), CheckLevel.ok)
        : median < 250
            ? (s.t('diag_quality_good'), CheckLevel.ok)
            : (s.t('diag_quality_slow'), CheckLevel.warn);
    report('latency', CheckResult(true, '$median ms ($quality)', level));
    passed++;
  } catch (_) {
    report('latency', CheckResult(false, s.t('diag_latency_fail')));
  }
  return passed;
}

/// Summary line and its level for [passed] of [total].
(String, CheckLevel) diagnosticsSummary(int passed, int total, Strings s) {
  if (passed == total) return (s.t('diag_all_ok', {'passed': passed, 'total': total}), CheckLevel.ok);
  if (passed >= 3) return (s.t('diag_partial', {'passed': passed, 'total': total}), CheckLevel.warn);
  return (s.t('diag_problems', {'passed': passed, 'total': total}), CheckLevel.bad);
}
