/// Invitation links: `https://secureshare-relay.duckdns.org/r#abcd-1234`.
///
/// The code is in the fragment (after `#`), which browsers never send to the
/// server — the relay still never learns the session code. With the app
/// installed the link opens it (Android App Link, verified through
/// /.well-known/assetlinks.json); otherwise the /r page shows the code and
/// how to get the app.
library;

import 'controller.dart' show normalizeCode;

const inviteHost = 'secureshare-relay.duckdns.org';
const invitePath = '/r';

String inviteLink(String code) => 'https://$inviteHost$invitePath#$code';

/// The session code from an invitation link, or null if [link] is not one.
String? codeFromInvite(String link) {
  final uri = Uri.tryParse(link.trim());
  if (uri == null || uri.scheme != 'https' || uri.host != inviteHost) return null;
  if (uri.path != invitePath && uri.path != '$invitePath/') return null;
  // `?c=` comes from the /r page's "Open in SecureShare" button (intent: URL,
  // never requested over HTTP); shared links carry the code after `#`
  final code = uri.fragment.isNotEmpty ? uri.fragment : (uri.queryParameters['c'] ?? '');
  return normalizeCode(Uri.decodeComponent(code));
}
