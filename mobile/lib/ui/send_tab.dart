library;

import 'package:flutter/material.dart';

import '../protocol/constants.dart' show maxFileSize;
import 'app.dart';

class SendTab extends StatelessWidget {
  const SendTab({super.key});

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
    final theme = Theme.of(context);
    final f = c.selected;
    final tooLarge = f != null && f.size > maxFileSize;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Text(s.t('send_choose_file'), style: theme.textTheme.titleMedium),
        const SizedBox(height: 12),
        if (f == null)
          OutlinedButton.icon(
            key: const Key('choose-file'),
            onPressed: c.pickFile,
            icon: const Icon(Icons.attach_file),
            label: Text(s.t('m_choose_file')),
            style: OutlinedButton.styleFrom(minimumSize: const Size.fromHeight(72)),
          )
        else
          Card(
            child: ListTile(
              key: const Key('selected-file'),
              leading: const Icon(Icons.insert_drive_file_outlined),
              title: Text(f.name, maxLines: 2, overflow: TextOverflow.ellipsis),
              subtitle: Text(f.size >= 0 ? s.size(f.size) : s.t('m_file_unknown_size')),
              trailing: TextButton(
                key: const Key('change-file'),
                onPressed: c.pickFile,
                child: Text(s.t('m_change_file')),
              ),
            ),
          ),
        if (tooLarge) ...[
          const SizedBox(height: 8),
          Text(
            s.t('file_size_warning', {'max_size': s.size(maxFileSize)}),
            style: TextStyle(color: theme.colorScheme.error),
          ),
        ],
        const SizedBox(height: 24),
        FilledButton.icon(
          key: const Key('send'),
          onPressed: f == null || tooLarge ? null : c.startSend,
          icon: const Icon(Icons.send),
          label: Text(s.t('m_send')),
          style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(52)),
        ),
        const SizedBox(height: 24),
        Text(s.t('m_share_hint'), style: theme.textTheme.bodySmall),
      ],
    );
  }
}

/// Large, readable code with a label above it (session or verification code).
class CodeText extends StatelessWidget {
  const CodeText(this.code, {super.key});
  final String code;

  @override
  Widget build(BuildContext context) => FittedBox(
        fit: BoxFit.scaleDown,
        child: SelectableText(
          code,
          key: const Key('code-text'),
          style: Theme.of(context).textTheme.displaySmall?.copyWith(
                fontFamily: 'monospace',
                fontWeight: FontWeight.w600,
                letterSpacing: 2,
              ),
        ),
      );
}
