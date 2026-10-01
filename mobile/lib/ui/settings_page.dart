library;

import 'package:flutter/material.dart';

import '../app/i18n.dart';
import '../transfer/handshake.dart' show appVersion;
import 'app.dart';
import 'update_ui.dart';

const githubUrl = 'https://github.com/artmarchenko/SecureShare';
const donateUrl = 'https://ko-fi.com/secureshare';

class SettingsPage extends StatelessWidget {
  const SettingsPage({super.key});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.strings;
    final theme = Theme.of(context);

    Future<void> choose(String? lang) async {
      await app.settings.setLanguage(lang);
      s.lang = lang ?? languageForLocale(WidgetsBinding.instance.platformDispatcher.locale.languageCode);
    }

    return ListenableBuilder(
      listenable: Listenable.merge([s, app.settings]),
      builder: (context, _) => _build(context, app, s, theme, choose),
    );
  }

  Widget _build(BuildContext context, AppServices app, Strings s, ThemeData theme, Future<void> Function(String?) choose) {
    final current = app.settings.language; // null = system
    return Scaffold(
      appBar: AppBar(title: Text(s.t('m_settings'))),
      body: ListView(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
            child: Text(s.t('m_language'), style: theme.textTheme.titleSmall),
          ),
          RadioGroup<String>(
            groupValue: current ?? '',
            onChanged: (v) => choose(v == null || v.isEmpty ? null : v),
            child: Column(
              children: [
                RadioListTile<String>(key: const Key('lang-system'), value: '', title: Text(s.t('m_language_system'))),
                for (final l in languages)
                  RadioListTile<String>(key: Key('lang-$l'), value: l, title: Text(languageNames[l]!)),
              ],
            ),
          ),
          const Divider(),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
            child: Text(s.t('m_about'), style: theme.textTheme.titleSmall),
          ),
          ListTile(
            title: const Text('SecureShare'),
            subtitle: Text('${s.t('m_version', {'version': appVersion})}\n${s.t('m_compat')}'),
            isThreeLine: true,
          ),
          const UpdateTile(),
          ListTile(
            leading: const Icon(Icons.code),
            title: Text(s.t('m_source_code')),
            onTap: () => app.device.openUrl(githubUrl),
          ),
          ListTile(
            leading: const Icon(Icons.favorite_outline),
            title: Text(s.t('m_support')),
            onTap: () => app.device.openUrl(donateUrl),
          ),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Text(s.t('copyright'), style: theme.textTheme.bodySmall),
          ),
        ],
      ),
    );
  }
}
