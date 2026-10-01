/// Main screen: Send / Receive tabs, or the running transfer.
library;

import 'package:flutter/material.dart';

import '../app/controller.dart';
import 'app.dart';
import 'diagnostics_page.dart';
import 'help_page.dart';
import 'receive_tab.dart';
import 'send_tab.dart';
import 'settings_page.dart';
import 'transfer_view.dart';
import 'update_ui.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  int _tab = 0;
  int _seenShares = 0;
  int _seenInvites = 0;

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final c = app.controller;
    final s = app.strings;
    return ListenableBuilder(
      listenable: Listenable.merge([c, s]),
      builder: (context, _) {
        if (c.sharedFileCount != _seenShares) {
          _seenShares = c.sharedFileCount;
          _tab = 0; // a file shared from another app → Send
        }
        if (c.inviteCount != _seenInvites) {
          _seenInvites = c.inviteCount;
          _tab = 1; // an invitation link → Receive
        }
        final error = c.error;
        if (error != null) {
          WidgetsBinding.instance.addPostFrameCallback((_) {
            c.clearError();
            ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(error)));
          });
        }
        final idle = c.phase == Phase.idle;
        return Scaffold(
          appBar: AppBar(
            title: const Text('SecureShare'),
            actions: [
              IconButton(
                key: const Key('help'),
                tooltip: s.t('help_title'),
                icon: const Icon(Icons.help_outline),
                onPressed: () => _open(context, const HelpPage()),
              ),
              PopupMenuButton<String>(
                key: const Key('menu'),
                onSelected: (v) => _open(context, v == 'diag' ? const DiagnosticsPage() : const SettingsPage()),
                itemBuilder: (_) => [
                  PopupMenuItem(value: 'diag', child: Text(s.t('diag_title'))),
                  PopupMenuItem(value: 'settings', child: Text(s.t('m_settings'))),
                ],
              ),
            ],
          ),
          body: SafeArea(
            child: idle
                ? Column(children: [
                    const UpdateBanner(),
                    Expanded(child: _tab == 0 ? const SendTab() : const ReceiveTab()),
                  ])
                : const TransferView(),
          ),
          bottomNavigationBar: idle
              ? NavigationBar(
                  selectedIndex: _tab,
                  onDestinationSelected: (i) => setState(() => _tab = i),
                  destinations: [
                    NavigationDestination(
                        key: const Key('tab-send'), icon: const Icon(Icons.upload_file), label: s.t('m_tab_send')),
                    NavigationDestination(
                        key: const Key('tab-receive'), icon: const Icon(Icons.download), label: s.t('m_tab_receive')),
                  ],
                )
              : null,
        );
      },
    );
  }

  void _open(BuildContext context, Widget page) =>
      Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => page));
}
