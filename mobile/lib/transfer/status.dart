/// Transfer status reporting — same message keys and phase table as
/// `_STATE_FOR_MESSAGE` in app/ws_relay.py, so the UI can reuse the
/// desktop translations (app/lang/*.json).
library;

enum TransferState { connecting, waiting, keyExchange, verifying, transferring, done, error }

typedef StatusCallback = void Function(String key, Map<String, Object?> args);
typedef StateCallback = void Function(TransferState state);
typedef ProgressCallback = void Function(int done, int total, double bytesPerSecond);

/// Asks the user to compare [code] with the other device; true = matches.
typedef VerifyCallback = Future<bool> Function(String code);

const Map<String, TransferState> stateForMessage = {
  'relay_connecting_to': TransferState.connecting,
  'relay_reconnecting_to': TransferState.connecting,
  'relay_waiting_receiver': TransferState.waiting,
  'relay_waiting_sender': TransferState.waiting,
  'relay_waiting_meta': TransferState.waiting,
  'relay_waiting_meta_ack': TransferState.waiting,
  'relay_waiting_integrity': TransferState.waiting,
  'relay_key_exchange': TransferState.keyExchange,
  'relay_verify_code': TransferState.verifying,
  'relay_sending': TransferState.transferring,
  'relay_sending_resume': TransferState.transferring,
  'relay_receiving': TransferState.transferring,
  'relay_receiving_resume': TransferState.transferring,
  'relay_file_sent_ok': TransferState.done,
  'relay_saved': TransferState.done,
  'relay_file_read_error': TransferState.error,
  'relay_retries_exhausted': TransferState.error,
  'relay_connect_error': TransferState.error,
  'relay_key_exchange_error': TransferState.error,
  'relay_key_format_error': TransferState.error,
  'relay_key_decrypt_error': TransferState.error,
  'relay_key_message_error': TransferState.error,
  'relay_incompatible': TransferState.error,
  'relay_commit_mismatch': TransferState.error,
  'relay_auto_verify_error': TransferState.error,
  'relay_verify_rejected': TransferState.error,
  'relay_verify_error': TransferState.error,
  'relay_verify_format_error': TransferState.error,
  'relay_verify_decrypt_error': TransferState.error,
  'relay_peer_rejected': TransferState.error,
  'relay_verify_msg_error': TransferState.error,
  'relay_meta_timeout': TransferState.error,
  'relay_meta_unexpected': TransferState.error,
  'relay_integrity_timeout': TransferState.error,
  'relay_unsafe_filename': TransferState.error,
  'relay_path_traversal': TransferState.error,
  'relay_invalid_filesize': TransferState.error,
  'relay_file_too_large': TransferState.error,
  'relay_part_open_error': TransferState.error,
  'relay_file_create_error': TransferState.error,
  'relay_hash_mismatch_recv': TransferState.error,
  'transfer_error_generic': TransferState.error,
};
