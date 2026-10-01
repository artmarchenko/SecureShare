/// What the app needs from Android, behind an interface so widget tests can
/// use a fake. The real implementation talks to NativeBridge.kt.
library;

import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';

import '../transfer/storage.dart' show FileSource;

/// A file chosen by the user (or shared from another app), kept open
/// natively until released; read it through [Device.fileSource].
class PickedFile {
  const PickedFile({required this.handle, required this.name, required this.size});

  final int handle;
  final String name;
  final int size;
}

/// Contents of the transfer notification.
class ServiceStatus {
  const ServiceStatus(
      {required this.title, required this.text, this.progress = -1, required this.cancelLabel, this.upload = true});

  final String title, text, cancelLabel;
  final int progress; // 0..1000, -1 = indeterminate
  final bool upload; // icon: sending or receiving
}

abstract class Device {
  Future<PickedFile?> pickFile();

  /// A file shared to the app ("Share → SecureShare"), at most once.
  Future<PickedFile?> takeSharedFile();
  Future<void> releaseFile(int handle);

  /// Random-access reading of a picked file, for the sender.
  FileSource fileSource(PickedFile file);

  Future<Directory> receiveDir();
  Future<Directory> appDir();

  /// Asks for the storage permission where needed (Android 10 and older).
  Future<bool> ensureStoragePermission();
  Future<void> requestNotificationPermission();

  Future<void> startService(ServiceStatus status);
  Future<void> updateService(ServiceStatus status);
  Future<void> stopService();

  Future<bool> openFile(String path);
  Future<bool> shareText(String text);
  Future<bool> openUrl(String url);

  /// Fires when a file was shared to the running app.
  Stream<void> get sharedFileArrived;

  /// Fires when the user taps Cancel in the transfer notification.
  Stream<void> get cancelRequested;
}

class NativeDevice implements Device {
  NativeDevice() {
    _channel.setMethodCallHandler((call) async {
      switch (call.method) {
        case 'sharedFile':
          _shared.add(null);
        case 'cancelRequested':
          _cancel.add(null);
        case 'selfTest':
          _selfTest.add(null);
      }
    });
  }

  static const _channel = MethodChannel('secureshare/native');
  final _shared = StreamController<void>.broadcast();
  final _cancel = StreamController<void>.broadcast();
  final _selfTest = StreamController<void>.broadcast();

  /// The app was started with `--ez selftest true` (now or before Dart was ready).
  Stream<void> get selfTestRequested => _selfTest.stream;
  Future<bool> takeSelfTest() async => await _channel.invokeMethod<bool>('takeSelfTest') ?? false;

  PickedFile? _picked(Object? raw) {
    if (raw is! Map) return null;
    if (raw['error'] != null) throw FileSystemException('${raw['error']}');
    return PickedFile(
      handle: raw['handle'] as int,
      name: raw['name'] as String,
      size: (raw['size'] as num).toInt(),
    );
  }

  Map<String, Object> _status(ServiceStatus s) =>
      {'title': s.title, 'text': s.text, 'progress': s.progress, 'cancelLabel': s.cancelLabel, 'upload': s.upload};

  @override
  Future<PickedFile?> pickFile() async => _picked(await _channel.invokeMethod('pickFile'));
  @override
  Future<PickedFile?> takeSharedFile() async => _picked(await _channel.invokeMethod('takeSharedFile'));
  @override
  Future<void> releaseFile(int handle) => _channel.invokeMethod('releaseFile', {'handle': handle});
  @override
  FileSource fileSource(PickedFile file) => _NativeFileSource(file);
  @override
  Future<Directory> receiveDir() async => Directory((await _channel.invokeMethod<String>('receiveDir'))!);
  @override
  Future<Directory> appDir() async => Directory((await _channel.invokeMethod<String>('appDir'))!);
  @override
  Future<bool> ensureStoragePermission() async => await _channel.invokeMethod<bool>('requestStoragePermission') ?? false;
  @override
  Future<void> requestNotificationPermission() => _channel.invokeMethod('requestNotificationPermission');
  @override
  Future<void> startService(ServiceStatus status) => _channel.invokeMethod('startService', _status(status));
  @override
  Future<void> updateService(ServiceStatus status) => _channel.invokeMethod('updateService', _status(status));
  @override
  Future<void> stopService() => _channel.invokeMethod('stopService');
  @override
  Future<bool> openFile(String path) async => await _channel.invokeMethod<bool>('openFile', {'path': path}) ?? false;
  @override
  Future<bool> shareText(String text) async => await _channel.invokeMethod<bool>('shareText', {'text': text}) ?? false;
  @override
  Future<bool> openUrl(String url) async => await _channel.invokeMethod<bool>('openUrl', {'url': url}) ?? false;
  @override
  Stream<void> get sharedFileArrived => _shared.stream;
  @override
  Stream<void> get cancelRequested => _cancel.stream;
}

/// Reads a picked file through NativeBridge (positional reads, native SHA-256).
class _NativeFileSource implements FileSource {
  _NativeFileSource(this.file);
  final PickedFile file;

  @override
  String get name => file.name;

  @override
  Future<int> length() async => file.size;

  @override
  Future<List<int>> read(int offset, int length) async =>
      (await NativeDevice._channel.invokeMethod<Uint8List>(
          'readFile', {'handle': file.handle, 'offset': offset, 'length': length}))!;

  @override
  Future<String> sha256Hex() async =>
      (await NativeDevice._channel.invokeMethod<String>('hashFile', {'handle': file.handle}))!;

  @override
  Future<void> close() async {} // released by the controller (the file stays selected for a retry)
}
