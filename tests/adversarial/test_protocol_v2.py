"""Protocol v2 properties exercised against the real receiver and relay."""

from __future__ import annotations

import hashlib
import os
import threading
import time

from app.config import VPS_CHUNK_SIZE
from app.crypto_utils import SessionSecrets
from app.ws_relay import TransferState, VPSRelayReceiver
from tests.helpers.scripted_peer import ScriptedPeer


def _code() -> str:
    raw = os.urandom(4).hex()
    return f"{raw[:4]}-{raw[4:]}"


def _start_receiver(code, inbox, verify_calls=None):
    log, states, result = [], [], []

    def verify(c):
        if verify_calls is not None:
            verify_calls.append(c)
        return True
    receiver = VPSRelayReceiver(code, inbox, on_status=log.append, on_state=states.append, on_verify=verify)
    thread = threading.Thread(target=lambda: result.append(receiver.receive()), daemon=True)
    thread.start()
    return receiver, thread, log, states, result


def test_key_swapped_after_commitment_is_refused_without_retry(relay, tmp_path):
    # S1: revealing a key other than the committed one is what a relay
    # substituting keys would have to do — the receiver stops for good.
    code = _code()
    verify_calls: list = []
    receiver, thread, log, states, result = _start_receiver(code, tmp_path, verify_calls)
    peer = ScriptedPeer(relay.url, code)
    peer.handshake(reveal_key=os.urandom(32))
    thread.join(20)
    peer.close()
    assert not thread.is_alive()
    assert result == [None]
    assert verify_calls == []                      # the user is never asked
    assert "relay_commit_mismatch" in log
    assert TransferState.ERROR in states
    assert not any(line.startswith("relay_reconnecting") for line in log)


def test_relabelled_chunk_is_rejected_and_requested_again(relay, tmp_path):
    # S4: the chunk number is authenticated; a frame moved to another slot
    # does not decrypt, so it is dropped and asked for again.
    data = os.urandom(2 * VPS_CHUNK_SIZE)
    sha = hashlib.sha256(data).hexdigest()
    code = _code()
    receiver, thread, log, states, result = _start_receiver(code, tmp_path)
    peer = ScriptedPeer(relay.url, code)
    peer.handshake()
    peer.verify()
    peer.send_ctl({"type": "relay_meta", "name": "f.bin", "size": len(data), "sha256": sha,
                   "chunk_size": VPS_CHUNK_SIZE, "total_chunks": 2, "transfer_id": ""})
    assert peer.recv_ctl()["type"] == "relay_meta_ack"
    peer.send_chunk(0, data[VPS_CHUNK_SIZE:], claimed_seq=1)   # chunk "0" relabelled as 1
    peer.send_chunk(0, data[:VPS_CHUNK_SIZE])
    peer.send_ctl({"type": "relay_done", "sha256": sha, "total_chunks": 2})
    assert peer.recv_ctl() == {"type": "relay_retransmit", "missing": [1]}
    peer.send_chunk(1, data[VPS_CHUNK_SIZE:])
    peer.send_ctl({"type": "relay_done", "sha256": sha, "total_chunks": 2})
    assert peer.recv_ctl() == {"type": "relay_done_ack", "verified": True}
    thread.join(20)
    peer.close()
    assert result[0].read_bytes() == data


def test_relay_never_receives_the_session_code(relay, tmp_path):
    # S3: the relay pairs clients by a scrypt-derived room ID.
    code = _code()
    receiver, thread, *_ = _start_receiver(code, tmp_path)
    deadline = time.monotonic() + 10
    while not relay.server._rooms and time.monotonic() < deadline:
        time.sleep(0.05)
    rooms = set(relay.server._rooms)
    receiver.cancel()
    thread.join(10)
    expected = hashlib.sha256(SessionSecrets.from_code(code).room_id.encode()).hexdigest()[:32]
    assert expected in rooms
    assert hashlib.sha256(code.encode()).hexdigest()[:32] not in rooms


def test_version_hint_when_nobody_shows_up():
    # A v3.x peer uses a different room, so a v4 client just sees no one arrive.
    from app.crypto_utils import ROLE_RECEIVER
    from app.ws_relay import _do_key_exchange

    class SilentRelay:
        def send_binary(self, data):
            pass

        def recv(self):
            raise TimeoutError("timed out")
    emitted: list = []
    crypto, fatal, proven = _do_key_exchange(
        SilentRelay(), SessionSecrets.from_code("ab12-cd34"), ROLE_RECEIVER,
        lambda key, **kw: emitted.append(key))
    assert crypto is None and not fatal and not proven
    assert emitted[-2:] == ["relay_key_exchange_error", "relay_peer_version_hint"]


def test_old_protocol_peer_is_refused_for_good(relay, tmp_path):
    code = _code()
    receiver, thread, log, states, result = _start_receiver(code, tmp_path)
    peer = ScriptedPeer(relay.url, code)
    peer.send_sig({"type": "commit", "commit": "AA==", "protocol_version": 1, "app_version": "3.4.0"})
    thread.join(20)
    peer.close()
    assert result == [None] and "relay_incompatible" in log
    assert not any(line.startswith("relay_reconnecting") for line in log)
