library;

import 'package:flutter/material.dart';

import '../app/i18n.dart';
import '../protocol/constants.dart' show maxFileSize;
import 'app.dart';

class HelpPage extends StatelessWidget {
  const HelpPage({super.key});

  @override
  Widget build(BuildContext context) {
    final s = AppScope.of(context).strings;
    final theme = Theme.of(context);
    final sections = [
      ('help_send_title', 'm_help_send_body'),
      ('help_recv_title', 'm_help_recv_body'),
      ('help_verify_title', 'help_verify_body'),
      ('m_help_background_title', 'm_help_background_body'),
      ('help_reconnect_title', 'help_reconnect_body'),
      ('help_security_title', 'help_security_body'),
      ('help_limits_title', 'help_limits_body'),
    ];
    return Scaffold(
      appBar: AppBar(title: Text(s.t('help_title'))),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          for (final (title, body) in sections) ...[
            Text(s.t(title), style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(unwrap(s.t(body, {'max_gb': maxFileSize ~/ (1 << 30)}))),
            const SizedBox(height: 24),
          ],
        ],
      ),
    );
  }
}
