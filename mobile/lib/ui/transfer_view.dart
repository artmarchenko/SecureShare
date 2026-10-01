/// The running (or just finished) transfer: session code, verification,
/// progress, result and log.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../app/controller.dart';
import '../app/i18n.dart';
import '../app/invite.dart';
import '../transfer/status.dart';
import 'app.dart';
import 'send_tab.dart' show CodeText;

class TransferView extends StatelessWidget {
  const TransferView({super.key});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    return ListenableBuilder(
      listenable: Listenable.merge([app.controller, app.strings]),
      builder: (context, _) => _build(context, app),
    );
  }

  Widget _build(BuildContext context, AppServices app) {
    final c = app.controller;
    final s = app.strings;
    final showSessionCode = c.sending &&
        c.busy &&
        c.sessionCode != null &&
        c.verifyCode == null &&
        const {TransferState.connecting, TransferState.waiting, TransferState.keyExchange}.contains(c.state);
    return Column(
      children: [
        Expanded(
          child: ListView(
            key: const Key('transfer-list'),
            padding: const EdgeInsets.all(16),
            children: [
              _FileHeader(c: c, s: s),
              const SizedBox(height: 12),
              if (showSessionCode) _SessionCodeCard(code: c.sessionCode!),
              if (c.verifyCode != null) _VerifyCard(code: c.verifyCode!),
              _ProgressCard(c: c, s: s),
              if (c.phase == Phase.finished) _ResultCard(c: c, s: s),
              _LogCard(c: c, s: s),
            ],
          ),
        ),
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
          child: c.busy
              ? OutlinedButton.icon(
                  key: const Key('cancel'),
                  onPressed: c.cancel,
                  icon: const Icon(Icons.stop),
                  label: Text(plain(s.t('btn_cancel'))),
                  style: OutlinedButton.styleFrom(minimumSize: const Size.fromHeight(52)),
                )
              : FilledButton(
                  key: const Key('done'),
                  onPressed: c.reset,
                  style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(52)),
                  child: Text(s.t('m_new_transfer')),
                ),
        ),
      ],
    );
  }
}

class _FileHeader extends StatelessWidget {
  const _FileHeader({required this.c, required this.s});
  final TransferController c;
  final Strings s;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Row(
      children: [
        Icon(c.sending ? Icons.upload : Icons.download, size: 32, color: theme.colorScheme.primary),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                c.fileName.isEmpty ? (c.sending ? s.t('m_tab_send') : s.t('m_tab_receive')) : c.fileName,
                key: const Key('file-name'),
                style: theme.textTheme.titleMedium,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
              if (c.fileSize > 0) Text(s.size(c.fileSize), style: theme.textTheme.bodySmall),
            ],
          ),
        ),
      ],
    );
  }
}

class _SessionCodeCard extends StatelessWidget {
  const _SessionCodeCard({required this.code});
  final String code;

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.strings;
    final theme = Theme.of(context);
    return Card(
      key: const Key('session-code'),
      color: theme.colorScheme.primaryContainer,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            Text(s.t('m_code_title'), style: theme.textTheme.titleSmall),
            const SizedBox(height: 8),
            CodeText(code),
            const SizedBox(height: 4),
            Text(s.t('send_code_hint'), textAlign: TextAlign.center),
            const SizedBox(height: 8),
            Wrap(
              alignment: WrapAlignment.center,
              spacing: 8,
              children: [
                TextButton.icon(
                  key: const Key('copy-code'),
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: code));
                    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(s.t('m_copied'))));
                  },
                  icon: const Icon(Icons.copy),
                  label: Text(s.t('m_copy')),
                ),
                TextButton.icon(
                  key: const Key('share-code'),
                  onPressed: () =>
                      app.device.shareText(s.t('m_share_code_text', {'code': code, 'link': inviteLink(code)})),
                  icon: const Icon(Icons.share),
                  label: Text(s.t('m_share')),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _VerifyCard extends StatelessWidget {
  const _VerifyCard({required this.code});
  final String code;

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.strings;
    final theme = Theme.of(context);
    return Card(
      key: const Key('verify'),
      color: theme.colorScheme.tertiaryContainer,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(plain(s.t('verify_title')), style: theme.textTheme.titleMedium, textAlign: TextAlign.center),
            const SizedBox(height: 8),
            Text(unwrap(s.t('verify_prompt')).replaceAll('\n', ' '), textAlign: TextAlign.center),
            const SizedBox(height: 8),
            Center(child: CodeText(code)),
            const SizedBox(height: 8),
            Text(
              unwrap(s.t('verify_warning')).replaceAll('\n', ' '),
              textAlign: TextAlign.center,
              style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
            ),
            const SizedBox(height: 12),
            FilledButton.icon(
              key: const Key('codes-match'),
              onPressed: () => app.controller.confirmCode(true),
              icon: const Icon(Icons.check),
              label: Text(plain(s.t('btn_codes_match'))),
            ),
            const SizedBox(height: 8),
            OutlinedButton.icon(
              key: const Key('codes-differ'),
              onPressed: () => app.controller.confirmCode(false),
              icon: const Icon(Icons.close),
              label: Text(plain(s.t('btn_cancel_verify'))),
            ),
          ],
        ),
      ),
    );
  }
}

class _ProgressCard extends StatelessWidget {
  const _ProgressCard({required this.c, required this.s});
  final TransferController c;
  final Strings s;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final transferring = c.state == TransferState.transferring && c.total > 0;
    double? value;
    if (c.phase == Phase.finished) {
      value = c.outcome == Outcome.success ? 1 : (c.total > 0 ? c.fraction : 0);
    } else if (transferring) {
      value = c.fraction;
    }
    final details = <String>[];
    if (c.total > 0) details.add('${s.size(c.done)} / ${s.size(c.total)}');
    if (c.busy && transferring && c.speed > 0) {
      details.add(s.speed(c.speed));
      details.add(s.t('m_eta', {'eta': s.eta((c.total - c.done) / c.speed)}));
    }
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(c.stateText, key: const Key('state'), style: theme.textTheme.titleSmall),
            const SizedBox(height: 12),
            LinearProgressIndicator(key: const Key('progress'), value: value, minHeight: 8,
                borderRadius: BorderRadius.circular(4)),
            if (details.isNotEmpty) ...[
              const SizedBox(height: 8),
              Text(details.join(' · '), key: const Key('progress-details'), style: theme.textTheme.bodySmall),
            ],
          ],
        ),
      ),
    );
  }
}

class _ResultCard extends StatelessWidget {
  const _ResultCard({required this.c, required this.s});
  final TransferController c;
  final Strings s;

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final (icon, title, color) = switch (c.outcome) {
      Outcome.success => (Icons.check_circle, c.sending ? 'm_result_sent' : 'm_result_received', Colors.green),
      Outcome.cancelled => (Icons.cancel_outlined, 'm_result_cancelled', scheme.outline),
      _ => (Icons.error_outline, 'm_result_failed', scheme.error),
    };
    final saved = c.savedFile;
    final partial = c.outcome != Outcome.success && c.done > 0;
    return Card(
      key: const Key('result'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(icon, color: color),
                const SizedBox(width: 8),
                Expanded(child: Text(s.t(title), key: const Key('result-title'), style: theme.textTheme.titleMedium)),
              ],
            ),
            if (saved != null) ...[
              const SizedBox(height: 8),
              Text(saved.path, style: theme.textTheme.bodySmall),
              const SizedBox(height: 8),
              FilledButton.tonalIcon(
                key: const Key('open-file'),
                onPressed: () async {
                  final messenger = ScaffoldMessenger.of(context);
                  if (!await app.device.openFile(saved.path)) {
                    messenger.showSnackBar(SnackBar(content: Text(s.t('m_open_failed'))));
                  }
                },
                icon: const Icon(Icons.open_in_new),
                label: Text(s.t('m_open_file')),
              ),
            ],
            if (partial) ...[
              const SizedBox(height: 8),
              Text(s.t(c.sending ? 'm_resume_hint_send' : 'm_resume_hint_receive'), key: const Key('resume-hint')),
            ],
          ],
        ),
      ),
    );
  }
}

class _LogCard extends StatelessWidget {
  const _LogCard({required this.c, required this.s});
  final TransferController c;
  final Strings s;

  String _time(DateTime t) =>
      '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}:${t.second.toString().padLeft(2, '0')}';

  String text() => c.log.map((l) => '[${_time(l.time)}] ${s.t(l.key, l.args)}').join('\n');

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final app = AppScope.of(context);
    return Card(
      key: const Key('log'),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 8, 8, 16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(child: Text(s.t('m_log'), style: theme.textTheme.titleSmall)),
                IconButton(
                  key: const Key('copy-log'),
                  tooltip: plain(s.t('btn_copy_log')),
                  icon: const Icon(Icons.copy, size: 20),
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: text()));
                    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(plain(s.t('log_copied')))));
                  },
                ),
                IconButton(
                  key: const Key('share-log'),
                  tooltip: s.t('m_share'),
                  icon: const Icon(Icons.share, size: 20),
                  onPressed: () => app.device.shareText(text()),
                ),
              ],
            ),
            for (final line in c.log)
              Padding(
                padding: const EdgeInsets.only(top: 4, right: 8),
                child: Text.rich(
                  TextSpan(children: [
                    TextSpan(text: '${_time(line.time)}  ', style: TextStyle(color: theme.colorScheme.outline)),
                    TextSpan(text: s.t(line.key, line.args)),
                  ]),
                  style: theme.textTheme.bodySmall,
                ),
              ),
          ],
        ),
      ),
    );
  }
}
