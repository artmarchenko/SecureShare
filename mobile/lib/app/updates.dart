/// Update check: the newest `android-v*` GitHub release. Desktop releases
/// (`v*`) are ignored. Installing is up to the user (Android asks to
/// confirm, and only accepts an APK signed with the same key).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../transfer/handshake.dart' show appVersion;

const releasesApi = 'https://api.github.com/repos/artmarchenko/SecureShare/releases?per_page=30';

class AndroidRelease {
  const AndroidRelease({required this.version, required this.notes, required this.apkUrl, required this.page});
  final String version;
  final String notes; // the "Changes" section of the release text
  final String apkUrl;
  final String page;
}

List<int>? parseVersion(String v) {
  final m = RegExp(r'^(?:android-v)?(\d+)\.(\d+)\.(\d+)$').firstMatch(v.trim());
  return m == null ? null : [for (var i = 1; i <= 3; i++) int.parse(m[i]!)];
}

int compareVersions(List<int> a, List<int> b) {
  for (var i = 0; i < 3; i++) {
    if (a[i] != b[i]) return a[i].compareTo(b[i]);
  }
  return 0;
}

/// The newest published Android release in GitHub's release list JSON.
AndroidRelease? newestAndroidRelease(String json) {
  final list = jsonDecode(json);
  if (list is! List) return null;
  AndroidRelease? best;
  List<int>? bestV;
  for (final r in list.whereType<Map<String, dynamic>>()) {
    final tag = r['tag_name'];
    if (tag is! String || !tag.startsWith('android-v') || r['draft'] == true || r['prerelease'] == true) continue;
    final v = parseVersion(tag);
    if (v == null || (bestV != null && compareVersions(v, bestV) <= 0)) continue;
    final assets = (r['assets'] as List? ?? const []).whereType<Map<String, dynamic>>();
    final apk = assets.where((a) => a['name'] == 'SecureShare.apk').firstOrNull;
    if (apk == null) continue;
    bestV = v;
    best = AndroidRelease(
      version: v.join('.'),
      notes: _changes('${r['body'] ?? ''}'),
      apkUrl: '${apk['browser_download_url']}',
      page: '${r['html_url'] ?? ''}',
    );
  }
  return best;
}

String _changes(String body) {
  final m = RegExp(r'### Changes\s*\n([\s\S]*?)(?:\n### |\s*$)').firstMatch(body);
  final text = (m?[1] ?? '').replaceAll('**', '').trim();
  return text.length > 1500 ? '${text.substring(0, 1500)}…' : text;
}

Future<String> _get(Uri url) async {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
  try {
    final req = await client.getUrl(url);
    req.headers.set('Accept', 'application/vnd.github+json');
    req.headers.set('User-Agent', 'SecureShare-Android/$appVersion');
    final resp = await req.close().timeout(const Duration(seconds: 15));
    if (resp.statusCode != 200) throw HttpException('HTTP ${resp.statusCode}', uri: url);
    return await resp.transform(utf8.decoder).join().timeout(const Duration(seconds: 15));
  } finally {
    client.close(force: true);
  }
}

enum UpdateStatus { idle, checking, upToDate, available, failed }

class Updates extends ChangeNotifier {
  Updates({Future<String> Function(Uri url)? fetch, this.current = appVersion}) : _fetch = fetch ?? _get;

  final Future<String> Function(Uri url) _fetch;
  final String current;
  UpdateStatus status = UpdateStatus.idle;
  AndroidRelease? release;
  String? error;
  bool dismissed = false; // "Later" for this run of the app

  bool get showBanner => status == UpdateStatus.available && !dismissed;

  Future<void> check() async {
    if (status == UpdateStatus.checking) return;
    status = UpdateStatus.checking;
    notifyListeners();
    try {
      final r = newestAndroidRelease(await _fetch(Uri.parse(releasesApi)));
      final newer = r != null && compareVersions(parseVersion(r.version)!, parseVersion(current)!) > 0;
      release = newer ? r : null;
      status = newer ? UpdateStatus.available : UpdateStatus.upToDate;
      error = null;
    } catch (e) {
      status = UpdateStatus.failed;
      error = e.toString();
    }
    notifyListeners();
  }

  void dismiss() {
    dismissed = true;
    notifyListeners();
  }
}
