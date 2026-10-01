/// State of the app's one transfer at a time: drives the transfer engine,
/// collects its status for the screens and keeps the foreground service
/// notification up to date. No widgets here — tested with fakes.
library;

import 'dart:async';
import 'dart:io';
import 'dart:math';

import 'package:flutter/foundation.dart';

import '../transfer/peer.dart';
import '../transfer/receiver.dart';
import '../transfer/sender.dart';
import '../transfer/status.dart';
import '../transfer/storage.dart';
import 'device.dart';
import 'i18n.dart';

// ── Engine seam (the real one is the relay engine; tests script their own) ──

class EngineCallbacks {
  const EngineCallbacks({required this.onStatus, required this.onState, required this.onProgress, required this.onVerify});
  final StatusCallback onStatus;
  final StateCallback onState;
  final ProgressCallback onProgress;
  final VerifyCallback onVerify;
}

abstract class TransferJob {
  /// Sender: true on success. Receiver: the saved File, or null.
  Future<Object?> run();
  void cancel();
}

abstract class TransferEngine {
  TransferJob sender(String code, FileSource source, EngineCallbacks cb);
  TransferJob receiver(String code, ReceiveFolder folder, EngineCallbacks cb);
}

class RelayEngine implements TransferEngine {
  const RelayEngine([this.options = const TransferOptions()]);
  final TransferOptions options;

  @override
  TransferJob sender(String code, FileSource source, EngineCallbacks cb) => _Job(TransferSender(code, source, options,
      onStatus: cb.onStatus, onState: cb.onState, onProgress: cb.onProgress, onVerify: cb.onVerify));

  @override
  TransferJob receiver(String code, ReceiveFolder folder, EngineCallbacks cb) => _Job(TransferReceiver(code, folder, options,
      onStatus: cb.onStatus, onState: cb.onState, onProgress: cb.onProgress, onVerify: cb.onVerify));
}

class _Job implements TransferJob {
  _Job(this.peer);
  final RelayPeer peer;

  @override
  Future<Object?> run() {
    final peer = this.peer;
    return peer is TransferSender ? peer.send() : (peer as TransferReceiver).receive();
  }

  @override
  void cancel() => peer.cancel();
}

// ── Session codes ──

/// A new session code like the desktop's: `a7f3-bc21`.
String newSessionCode([Random? random]) {
  final r = random ?? Random.secure();
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  String part() => List.generate(4, (_) => chars[r.nextInt(chars.length)]).join();
  return '${part()}-${part()}';
}

/// The canonical form of a typed code (`ABCD 1234` → `abcd-1234`), or null.
String? normalizeCode(String input) {
  final s = input.replaceAll(RegExp(r'\s'), '').toLowerCase();
  if (RegExp(r'^[a-z0-9]{8}$').hasMatch(s)) return '${s.substring(0, 4)}-${s.substring(4)}';
  if (RegExp(r'^[a-z0-9]{4}-[a-z0-9]{4}$').hasMatch(s)) return s;
  return null;
}

// ── Controller ──

enum Phase { idle, running, finished }

enum Outcome { success, failed, cancelled }

class LogLine {
  LogLine(this.key, [this.args = const {}]) : time = DateTime.now();
  final DateTime time;
  final String key;
  final Map<String, Object?> args;
}

class TransferController extends ChangeNotifier {
  TransferController({
    required this.device,
    required this.strings,
    this.engine = const RelayEngine(),
    String Function()? newCode,
    this.verifyTimeout = const Duration(seconds: 120),
  }) : _newCode = newCode ?? newSessionCode {
    _subs.add(device.sharedFileArrived.listen((_) => takeSharedFile()));
    _subs.add(device.cancelRequested.listen((_) => cancel()));
  }

  final Device device;
  final Strings strings;
  final TransferEngine engine;
  final Duration verifyTimeout;
  final String Function() _newCode;
  final _subs = <StreamSubscription<void>>[];

  /// The file chosen on the Send tab.
  PickedFile? selected;

  /// Set when a file is shared from another app: the UI switches to Send.
  int sharedFileCount = 0;

  Phase phase = Phase.idle;
  bool sending = true;
  String? sessionCode;
  String fileName = '';
  int fileSize = 0;
  TransferState state = TransferState.connecting;
  final log = <LogLine>[];
  int done = 0, total = 0;
  double speed = 0;
  String? verifyCode; // a code waiting for the user's decision
  Outcome? outcome;
  File? savedFile;
  String? error; // a problem before the transfer could start (shown once)

  TransferJob? _job;
  Completer<bool>? _verify;
  Timer? _verifyTimer;
  bool _cancelled = false;
  bool _askedNotifications = false;
  int _lastServicePercent = -1;

  bool get busy => phase == Phase.running;
  double get fraction => total > 0 ? (done / total).clamp(0, 1).toDouble() : 0;

  // ── Choosing the file ──

  Future<void> pickFile() async {
    try {
      final f = await device.pickFile();
      if (f != null) _select(f);
    } catch (e) {
      _setError(strings.t('relay_file_read_error', {'error': e}));
    }
  }

  Future<void> takeSharedFile() async {
    try {
      final f = await device.takeSharedFile();
      if (f == null) return;
      if (busy) {
        await device.releaseFile(f.handle); // one transfer at a time
        return;
      }
      _select(f);
      sharedFileCount++;
      notifyListeners();
    } catch (e) {
      _setError(strings.t('relay_file_read_error', {'error': e}));
    }
  }

  void _select(PickedFile f) {
    final old = selected;
    if (old != null && old.handle != f.handle) unawaited(device.releaseFile(old.handle));
    selected = f;
    notifyListeners();
  }

  void clearError() => error = null;

  void _setError(String message) {
    error = message;
    notifyListeners();
  }

  // ── Running a transfer ──

  Future<void> startSend() async {
    final f = selected;
    if (f == null || busy) return;
    _begin(sending: true, name: f.name, size: f.size);
    sessionCode = _newCode();
    notifyListeners();
    final result = await _run(engine.sender(sessionCode!, device.fileSource(f), _callbacks()));
    final ok = result == true;
    _finish(ok);
    if (ok) {
      selected = null;
      unawaited(device.releaseFile(f.handle));
    }
  }

  Future<void> startReceive(String code) async {
    if (busy) return;
    if (!await device.ensureStoragePermission()) {
      return _setError(strings.t('m_storage_denied'));
    }
    final Directory dir;
    try {
      dir = await device.receiveDir();
    } catch (e) {
      return _setError(strings.t('relay_file_create_error', {'error': e}));
    }
    _begin(sending: false, name: '', size: 0);
    sessionCode = code;
    notifyListeners();
    final result = await _run(engine.receiver(code, ReceiveFolder(dir), _callbacks()));
    savedFile = result is File ? result : null;
    _finish(savedFile != null);
  }

  void cancel() {
    if (!busy || _cancelled) return;
    _cancelled = true;
    _answerVerify(false);
    _job?.cancel();
    notifyListeners();
  }

  /// The user's answer to the verification code.
  void confirmCode(bool matches) => _answerVerify(matches);

  /// Back to the tabs after a finished transfer.
  void reset() {
    if (busy) return;
    phase = Phase.idle;
    outcome = null;
    savedFile = null;
    notifyListeners();
  }

  EngineCallbacks _callbacks() => EngineCallbacks(
        onStatus: _onStatus,
        onState: _onState,
        onProgress: _onProgress,
        onVerify: _onVerify,
      );

  void _begin({required bool sending, required String name, required int size}) {
    this.sending = sending;
    phase = Phase.running;
    fileName = name;
    fileSize = size;
    state = TransferState.connecting;
    log.clear();
    done = total = 0;
    speed = 0;
    outcome = null;
    savedFile = null;
    error = null;
    _cancelled = false;
    _lastServicePercent = -1;
    if (!_askedNotifications) {
      _askedNotifications = true;
      unawaited(device.requestNotificationPermission().catchError((_) {}));
    }
    unawaited(device.startService(_serviceStatus()).catchError((_) {}));
  }

  Future<Object?> _run(TransferJob job) async {
    _job = job;
    try {
      return await job.run();
    } catch (e) {
      _onStatus('transfer_error_generic', {'error': e});
      return null;
    } finally {
      _job = null;
    }
  }

  void _finish(bool ok) {
    _answerVerify(false);
    phase = Phase.finished;
    outcome = ok ? Outcome.success : (_cancelled ? Outcome.cancelled : Outcome.failed);
    if (ok) {
      state = TransferState.done;
      if (total == 0) total = fileSize;
      done = total;
      if (sending) {
        log.add(LogLine('transfer_complete_send'));
      } else {
        log.add(LogLine('transfer_complete_recv', {'path': savedFile!.path}));
      }
    } else if (_cancelled) {
      log.add(LogLine('transfer_cancelled_user'));
    } else {
      state = TransferState.error;
      log.add(LogLine(sending ? 'transfer_error_send' : 'transfer_error_recv'));
    }
    unawaited(device.stopService().catchError((_) {}));
    notifyListeners();
  }

  void _onStatus(String key, Map<String, Object?> args) {
    log.add(LogLine(key, args));
    if (!sending && (key == 'relay_receiving' || key == 'relay_receiving_resume')) {
      fileName = '${args['filename'] ?? ''}';
      if (args['size'] is int) fileSize = args['size'] as int;
    }
    if (key == 'relay_file_renamed') fileName = '${args['filename'] ?? fileName}';
    _updateService(force: true);
    notifyListeners();
  }

  void _onState(TransferState s) {
    // a failed attempt may be retried: the final error is shown by _finish()
    if (s == TransferState.error && busy) s = TransferState.connecting;
    state = s;
    notifyListeners();
  }

  void _onProgress(int done, int total, double bytesPerSecond) {
    this.done = done;
    this.total = total;
    if (bytesPerSecond > 0) speed = bytesPerSecond;
    _updateService();
    notifyListeners();
  }

  Future<bool> _onVerify(String code) {
    final c = _verify = Completer<bool>();
    verifyCode = code;
    _verifyTimer = Timer(verifyTimeout, () {
      if (c.isCompleted) return;
      log.add(LogLine('verify_timeout'));
      _answerVerify(false);
    });
    _updateService(force: true);
    notifyListeners();
    return c.future;
  }

  void _answerVerify(bool matches) {
    _verifyTimer?.cancel();
    _verifyTimer = null;
    final c = _verify;
    _verify = null;
    if (verifyCode != null) {
      verifyCode = null;
      notifyListeners();
    }
    if (c != null && !c.isCompleted) c.complete(matches);
  }

  // ── Notification ──

  String get stateText => strings.t(switch (state) {
        TransferState.connecting => 'state_connecting',
        TransferState.waiting => 'state_waiting',
        TransferState.keyExchange => 'state_key_exchange',
        TransferState.verifying => 'state_verifying',
        TransferState.transferring => 'state_transferring',
        TransferState.done => 'state_done',
        TransferState.error => 'state_error',
      });

  ServiceStatus _serviceStatus() {
    final title = sending
        ? strings.t('m_notif_send', {'filename': fileName})
        : (fileName.isEmpty ? strings.t('m_notif_receive') : strings.t('m_notif_receive_file', {'filename': fileName}));
    String text;
    var progress = -1;
    if (verifyCode != null) {
      text = strings.t('m_notif_verify');
    } else if (state == TransferState.transferring && total > 0) {
      progress = (fraction * 1000).round();
      text = '${(fraction * 100).toStringAsFixed(0)}% · ${strings.size(done)} / ${strings.size(total)}';
      if (speed > 0) text += ' · ${strings.speed(speed)}';
    } else {
      text = plain(stateText);
    }
    return ServiceStatus(
        title: title, text: text, progress: progress, cancelLabel: plain(strings.t('btn_cancel')), upload: sending);
  }

  /// Notification updates: on every status, and on progress once per percent.
  void _updateService({bool force = false}) {
    if (!busy) return;
    final percent = (fraction * 100).floor();
    if (!force && percent == _lastServicePercent) return;
    _lastServicePercent = percent;
    unawaited(device.updateService(_serviceStatus()).catchError((_) {}));
  }

  @override
  void dispose() {
    for (final s in _subs) {
      s.cancel();
    }
    _verifyTimer?.cancel();
    super.dispose();
  }
}
