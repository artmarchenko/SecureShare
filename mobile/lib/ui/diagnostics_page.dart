library;

import 'package:flutter/material.dart';

import '../app/diagnostics.dart';
import 'app.dart';

const _labels = {
  'internet': 'diag_internet',
  'dns': 'diag_dns',
  'tls': 'diag_tls',
  'websocket': 'diag_websocket',
  'latency': 'diag_latency',
};

class DiagnosticsPage extends StatefulWidget {
  const DiagnosticsPage({super.key});

  @override
  State<DiagnosticsPage> createState() => _DiagnosticsPageState();
}

class _DiagnosticsPageState extends State<DiagnosticsPage> {
  final _rows = <String, CheckResult>{};
  int? _passed;
  bool _running = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (!_running && _passed == null) _run();
  }

  Future<void> _run() async {
    final app = AppScope.of(context);
    setState(() {
      _running = true;
      _rows.clear();
      _passed = null;
    });
    final passed = await app.diagnostics(app.relayUrl, app.strings, (check, result) {
      if (mounted) setState(() => _rows[check] = result);
    });
    if (mounted) {
      setState(() {
        _passed = passed;
        _running = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = AppScope.of(context).strings;
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    Color colorOf(CheckLevel l) => switch (l) {
          CheckLevel.ok => Colors.green,
          CheckLevel.warn => Colors.orange,
          CheckLevel.bad => scheme.error,
          CheckLevel.skipped => scheme.outline,
        };
    final summary = _passed == null ? null : diagnosticsSummary(_passed!, diagnosticChecks.length, s);
    return Scaffold(
      appBar: AppBar(title: Text(s.t('diag_title'))),
      body: ListView(
        padding: const EdgeInsets.symmetric(vertical: 8),
        children: [
          for (final check in diagnosticChecks)
            ListTile(
              key: Key('diag-$check'),
              title: Text(s.t(_labels[check]!)),
              subtitle: Text(_rows[check]?.detail ?? s.t('diag_checking')),
              trailing: switch (_rows[check]) {
                null => const SizedBox.square(dimension: 20, child: CircularProgressIndicator(strokeWidth: 2)),
                final r => Icon(
                    r.ok ? Icons.check_circle : Icons.cancel,
                    color: colorOf(r.level ?? (r.ok ? CheckLevel.ok : CheckLevel.bad)),
                  ),
              },
            ),
          if (summary != null)
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text(summary.$1, key: const Key('diag-summary'),
                  style: theme.textTheme.titleMedium?.copyWith(color: colorOf(summary.$2))),
            ),
          Padding(
            padding: const EdgeInsets.all(16),
            child: OutlinedButton(
              key: const Key('diag-again'),
              onPressed: _running ? null : _run,
              child: Text(s.t('m_run_again')),
            ),
          ),
        ],
      ),
    );
  }
}
