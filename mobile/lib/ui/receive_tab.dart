library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../app/controller.dart';
import 'app.dart';

class ReceiveTab extends StatefulWidget {
  const ReceiveTab({super.key});

  @override
  State<ReceiveTab> createState() => _ReceiveTabState();
}

class _ReceiveTabState extends State<ReceiveTab> {
  final _code = TextEditingController();
  bool _invalid = false;
  bool _fromInvite = false;

  @override
  void dispose() {
    _code.dispose();
    super.dispose();
  }

  Future<void> _paste() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text?.trim();
    if (text == null || text.isEmpty) return;
    // accept a whole shared message like "SecureShare code: abcd-1234"
    final match = RegExp(r'[A-Za-z0-9]{4}-?[A-Za-z0-9]{4}(?![A-Za-z0-9])').allMatches(text).lastOrNull;
    setState(() {
      _code.text = match?.group(0) ?? text;
      _invalid = false;
    });
  }

  void _start() {
    final code = normalizeCode(_code.text);
    if (code == null) {
      setState(() => _invalid = true);
      return;
    }
    FocusScope.of(context).unfocus();
    AppScope.of(context).controller.startReceive(code);
  }

  @override
  Widget build(BuildContext context) {
    final s = AppScope.of(context).strings;
    final c = AppScope.of(context).controller;
    return ListenableBuilder(listenable: Listenable.merge([s, c]), builder: (context, _) => _build(context));
  }

  Widget _build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.strings;
    final invite = app.controller.consumeInviteCode();
    if (invite != null) {
      _code.text = invite;
      _invalid = false;
      _fromInvite = true;
    }
    final theme = Theme.of(context);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Text(s.t('recv_enter_code'), style: theme.textTheme.titleMedium),
        const SizedBox(height: 12),
        TextField(
          key: const Key('code-input'),
          controller: _code,
          autocorrect: false,
          enableSuggestions: false,
          keyboardType: TextInputType.visiblePassword,
          textInputAction: TextInputAction.go,
          style: theme.textTheme.headlineSmall?.copyWith(fontFamily: 'monospace', letterSpacing: 2),
          decoration: InputDecoration(
            border: const OutlineInputBorder(),
            hintText: s.t('recv_code_placeholder'),
            errorText: _invalid ? s.t('m_invalid_code') : null,
            errorMaxLines: 3,
            suffixIcon: IconButton(
              key: const Key('paste'),
              tooltip: s.t('m_paste'),
              icon: const Icon(Icons.content_paste),
              onPressed: _paste,
            ),
          ),
          onChanged: (_) {
            if (_invalid || _fromInvite) {
              setState(() {
                _invalid = false;
                _fromInvite = false;
              });
            }
          },
          onSubmitted: (_) => _start(),
        ),
        if (_fromInvite) ...[
          const SizedBox(height: 8),
          Row(
            key: const Key('invite-hint'),
            children: [
              Icon(Icons.link, size: 18, color: theme.colorScheme.primary),
              const SizedBox(width: 8),
              Expanded(child: Text(s.t('m_invite_prefilled'), style: TextStyle(color: theme.colorScheme.primary))),
            ],
          ),
        ],
        const SizedBox(height: 24),
        FilledButton.icon(
          key: const Key('receive'),
          onPressed: _start,
          icon: const Icon(Icons.download),
          label: Text(s.t('m_receive')),
          style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(52)),
        ),
        const SizedBox(height: 24),
        Text(s.t('m_save_to', {'folder': s.t('m_downloads_folder')}), style: theme.textTheme.bodySmall),
      ],
    );
  }
}
