// The Dart protocol core must reproduce tests/vectors/protocol_v2.json
// (generated from the Python implementation) byte for byte.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:secureshare/protocol/constants.dart';
import 'package:secureshare/protocol/crypto_session.dart';
import 'package:secureshare/protocol/frames.dart';
import 'package:secureshare/protocol/secrets.dart';

final Map<String, dynamic> v =
    jsonDecode(File('../tests/vectors/protocol_v2.json').readAsStringSync()) as Map<String, dynamic>;
final Map<String, dynamic> h = v['handshake'] as Map<String, dynamic>;

Future<(CryptoSession, CryptoSession)> sessions(SessionSecrets secrets, String senderPriv, String receiverPriv) async {
  final s = await CryptoSession.create(secrets, roleSender, privateKey: unhex(senderPriv));
  final r = await CryptoSession.create(secrets, roleReceiver, privateKey: unhex(receiverPriv));
  await s.deriveSharedKey(r.publicKey);
  await r.deriveSharedKey(s.publicKey);
  return (s, r);
}

void main() {
  late SessionSecrets secrets;

  setUpAll(() async {
    secrets = await SessionSecrets.fromCode(h['code'] as String);
  });

  test('protocol version', () => expect(v['protocol_version'], protocolVersion));

  group('session secrets', () {
    for (final c in (v['session_secrets'] as List).cast<Map<String, dynamic>>()) {
      test('code ${jsonEncode(c['code'])}', () async {
        final sw = Stopwatch()..start();
        final sec = await SessionSecrets.fromCode(c['code'] as String);
        // ignore: avoid_print
        print('  scrypt+hkdf: ${sw.elapsedMilliseconds} ms');
        expect(hex(sec.master), c['master']);
        expect(sec.roomId, c['room_id']);
        expect(hex(sec.signalingKey), c['signaling_key']);
      });
    }
  });

  test('handshake values', () async {
    final (s, r) = await sessions(secrets, h['sender_private'] as String, h['receiver_private'] as String);
    expect(hex(s.publicKey), h['sender_public']);
    expect(hex(r.publicKey), h['receiver_public']);
    expect(hex(s.transcript), h['transcript']);
    expect(hex(r.transcript), h['transcript']);
    expect(hex(s.sharedKeyForTests), h['data_key']);
    expect(hex(r.sharedKeyForTests), h['data_key']);
    expect(await s.verificationCode(), h['verification_code']);
    expect(await r.verificationCode(), h['verification_code']);
    final c = h['commitment'] as Map<String, dynamic>;
    expect(hex(await commitment(s.publicKey, unhex(c['opening'] as String))), c['value']);
    expect(await checkCommitment(unhex(c['value'] as String), s.publicKey, unhex(c['opening'] as String)), isTrue);
    expect(await checkCommitment(unhex(c['value'] as String), r.publicKey, unhex(c['opening'] as String)), isFalse);
    final m = h['mac_example'] as Map<String, dynamic>;
    expect(hex(await s.mac(unhex(m['data'] as String))), m['mac']);
  });

  test('reconnect proofs', () async {
    final rc = h['reconnect'] as Map<String, dynamic>;
    final (s, r) = await sessions(secrets, h['sender_private'] as String, h['receiver_private'] as String);
    final (ps, pr) = await sessions(
        secrets, rc['previous_sender_private'] as String, rc['previous_receiver_private'] as String);
    expect(hex(ps.sharedKeyForTests), rc['previous_data_key']);
    expect(hex(await s.reconnectProof(ps)), rc['proof_by_sender']);
    expect(hex(await r.reconnectProof(pr)), rc['proof_by_receiver']);
    expect(await r.checkReconnectProof(pr, unhex(rc['proof_by_sender'] as String)), isTrue);
    expect(await s.checkReconnectProof(ps, unhex(rc['proof_by_receiver'] as String)), isTrue);
    // a proof is not accepted back by its own author (reflection)
    expect(await s.checkReconnectProof(ps, unhex(rc['proof_by_sender'] as String)), isFalse);
  });

  test('frames: exact encryption, decryption, decompression', () async {
    final (s, r) = await sessions(secrets, h['sender_private'] as String, h['receiver_private'] as String);
    for (final f in (v['frames'] as List).cast<Map<String, dynamic>>()) {
      final sender = f['author'] == roleSender;
      final author = sender ? s : r, reader = sender ? r : s;
      expect(author.sendCounter, f['counter'], reason: f['note'] as String);
      final wire = unhex(f['wire'] as String);
      if (f['type'] == 'C') {
        expect(wire[0], frameControl);
        expect(hex(await author.encrypt(unhex(f['plaintext'] as String), utf8.encode('C'))),
            hex(wire.sublist(1)), reason: f['note'] as String);
        expect(hex(await reader.decrypt(wire.sublist(1), utf8.encode('C'))), f['plaintext']);
      } else {
        final seq = wire.sublist(1, 5);
        expect(wire[0], frameData);
        final aad = [...utf8.encode('D'), ...seq];
        expect(hex(await author.encrypt(unhex(f['payload'] as String), aad)), hex(wire.sublist(5)),
            reason: f['note'] as String);
        final payload = await reader.decrypt(wire.sublist(5), aad);
        expect(hex(payload), f['payload']);
        expect(hex(decompressChunk(payload)), f['chunk']);
        // our own compressor makes a payload with the same flag that round-trips
        final mine = compressChunk(unhex(f['chunk'] as String));
        expect(mine[0], payload[0]);
        expect(hex(decompressChunk(mine)), f['chunk']);
      }
    }
  });

  test('a relabelled chunk does not decrypt', () async {
    final (s, r) = await sessions(secrets, h['sender_private'] as String, h['receiver_private'] as String);
    final body = await s.encrypt([1, 2, 3], [...utf8.encode('D'), 0, 0, 0, 7]);
    expect(() => r.decrypt(body, [...utf8.encode('D'), 0, 0, 0, 8]), throwsA(anything));
  });

  test('signaling frame decrypts, and ours decrypts too', () async {
    final sig = v['signaling'] as Map<String, dynamic>;
    final key = (await SessionSecrets.fromCode(sig['code'] as String)).signalingKey;
    final wire = unhex(sig['wire'] as String);
    expect(wire[0], frameSignaling);
    expect(hex(await signalingDecrypt(key, wire.sublist(1))), sig['plaintext']);
    final mine = await signalingEncrypt(key, unhex(sig['plaintext'] as String));
    expect(hex(await signalingDecrypt(key, mine)), sig['plaintext']);
  });

  test('zlib example decompresses', () {
    final z = v['zlib_example'] as Map<String, dynamic>;
    expect(hex(decompressChunk([compressedFlag, ...unhex(z['compressed'] as String)])), z['input']);
  });

  test('transfer ids', () async {
    for (final t in (v['transfer_id'] as List).cast<Map<String, dynamic>>()) {
      expect(await transferId(t['name'] as String, t['size'] as int, t['sha256'] as String), t['id']);
    }
  });

  test('safe file names', () {
    for (final c in (v['safe_file_names'] as List).cast<Map<String, dynamic>>()) {
      expect(safeFileName(c['raw'] as String?), c['expected'], reason: jsonEncode(c['raw']));
    }
  });
}
