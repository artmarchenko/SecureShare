/// Update banner (main screen) and details dialog.
library;

import 'package:flutter/material.dart';

import '../app/i18n.dart';
import '../app/updates.dart';
import 'app.dart';

class UpdateBanner extends StatelessWidget {
  const UpdateBanner({super.key});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.strings;
    return ListenableBuilder(
      listenable: app.updates,
      builder: (context, _) {
        final r = app.updates.release;
        if (!app.updates.showBanner || r == null) return const SizedBox.shrink();
        return MaterialBanner(
          key: const Key('update-banner'),
          leading: const Icon(Icons.system_update),
          content: Text(s.t('m_update_available', {'version': r.version})),
          actions: [
            TextButton(onPressed: app.updates.dismiss, child: Text(s.t('m_update_later'))),
            FilledButton.tonal(
              key: const Key('update-details'),
              onPressed: () => showUpdateDetails(context),
              child: Text(s.t('m_update_details')),
            ),
          ],
        );
      },
    );
  }
}

Future<void> showUpdateDetails(BuildContext context) {
  final app = AppScope.of(context);
  final s = app.strings;
  final r = app.updates.release!;
  return showDialog<void>(
    context: context,
    builder: (context) => AlertDialog(
      key: const Key('update-dialog'),
      title: Text(s.t('m_update_available', {'version': r.version})),
      content: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(s.t('update_whats_new'), style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 4),
            Text(r.notes.isEmpty ? s.t('update_no_description') : r.notes),
            const SizedBox(height: 16),
            Text(s.t('m_update_install_hint'), style: Theme.of(context).textTheme.bodySmall),
          ],
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(s.t('btn_close'))),
        FilledButton(
          key: const Key('update-download'),
          onPressed: () {
            app.device.openUrl(r.apkUrl);
            Navigator.pop(context);
          },
          child: Text(s.t('m_update_download')),
        ),
      ],
    ),
  );
}

/// Settings row: check now / result.
class UpdateTile extends StatelessWidget {
  const UpdateTile({super.key});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.strings;
    final u = app.updates;
    return ListenableBuilder(
      listenable: u,
      builder: (context, _) {
        final subtitle = switch (u.status) {
          UpdateStatus.checking => s.t('update_checking'),
          UpdateStatus.upToDate => plain(s.t('update_up_to_date', {'version': u.current})),
          UpdateStatus.available => s.t('m_update_available', {'version': u.release!.version}),
          UpdateStatus.failed => plain(s.t('update_check_failed', {'error': u.error ?? ''})),
          UpdateStatus.idle => null,
        };
        return ListTile(
          key: const Key('update-check'),
          leading: const Icon(Icons.system_update_outlined),
          title: Text(s.t('m_update_check')),
          subtitle: subtitle == null ? null : Text(subtitle, maxLines: 3, overflow: TextOverflow.ellipsis),
          onTap: u.status == UpdateStatus.checking
              ? null
              : () async {
                  if (u.status == UpdateStatus.available) return showUpdateDetails(context);
                  await u.check();
                },
        );
      },
    );
  }
}
