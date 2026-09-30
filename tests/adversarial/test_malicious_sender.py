"""The receiver must validate everything the other side sends."""

from __future__ import annotations

import hashlib
import os
import threading

import pytest

from app.config import VPS_CHUNK_SIZE, VPS_MAX_FILE_SIZE
from app.ws_relay import VPSRelayReceiver
from tests.helpers.scripted_peer import ScriptedPeer


def _code() -> str:
    raw = os.urandom(4).hex()
    return f"{raw[:4]}-{raw[4:]}"


class Session:
    def __init__(self, relay, save_dir):
        self.code = _code()
        self.log: list[str] = []
        self.result: list = []
        self.receiver = VPSRelayReceiver(self.code, save_dir, on_status=self.log.append, on_verify=lambda c: True)
        self.thread = threading.Thread(target=lambda: self.result.append(self.receiver.receive()), daemon=True)
        self.thread.start()
        self.peer = ScriptedPeer(relay.url, self.code)
        self.peer.handshake()
        self.peer.verify()

    def finish(self, timeout=30):
        self.thread.join(timeout)
        self.peer.close()
        assert not self.thread.is_alive()
        return self.result[0]


def meta(name="file.bin", size=10, sha="0" * 64, **extra):
    chunks = max(1, -(-size // VPS_CHUNK_SIZE)) if isinstance(size, int) else 1
    msg = {"type": "relay_meta", "name": name, "size": size, "sha256": sha,
           "chunk_size": VPS_CHUNK_SIZE, "total_chunks": chunks, "transfer_id": ""}
    msg.update(extra)
    return msg


@pytest.fixture
def inbox(tmp_path):
    d = tmp_path / "inbox"
    d.mkdir()
    return d


@pytest.mark.parametrize("name,expected", [
    ("../../evil.txt", "evil.txt"),
    ("..\\..\\evil.txt", "evil.txt"),
    ("C:\\Windows\\evil.txt", "evil.txt"),
    ("/etc/evil.txt", "evil.txt"),
], ids=["posix-dotdot", "win-dotdot", "win-absolute", "posix-absolute"])
def test_path_components_are_stripped(relay, inbox, tmp_path, name, expected):
    data = b"payload"
    s = Session(relay, inbox)
    s.peer.send_ctl(meta(name=name, size=len(data), sha=hashlib.sha256(data).hexdigest()))
    assert s.peer.recv_ctl()["type"] == "relay_meta_ack"
    s.peer.send_chunk(0, data)
    s.peer.send_ctl({"type": "relay_done", "sha256": hashlib.sha256(data).hexdigest(), "total_chunks": 1})
    assert s.peer.recv_ctl() == {"type": "relay_done_ack", "verified": True}
    saved = s.finish()
    # Security property on every OS: the file lands directly inside the inbox.
    assert saved is not None and saved.parent == inbox
    outside = [p for p in tmp_path.rglob("*evil.txt") if p.parent != inbox]
    assert outside == []
    assert saved == inbox / expected   # B11: same result on every OS


@pytest.mark.parametrize("name", ["..", ".", "", "bad\x00name"], ids=["dotdot", "dot", "empty", "nul"])
def test_unsafe_names_are_refused(relay, inbox, name):
    s = Session(relay, inbox)
    s.peer.send_ctl(meta(name=name))
    assert s.finish() is None
    assert list(inbox.iterdir()) == []


@pytest.mark.parametrize("size", [0, -1, "10", VPS_MAX_FILE_SIZE + 1], ids=["zero", "negative", "string", "over-limit"])
def test_invalid_sizes_are_refused(relay, inbox, size):
    s = Session(relay, inbox)
    s.peer.send_ctl(meta(size=size, total_chunks=1))
    assert s.finish() is None
    assert list(inbox.iterdir()) == []


@pytest.mark.parametrize("chunk_size", [0, -5, 64 * 1024 * 1024, "big"], ids=["zero", "negative", "64MB", "string"])
def test_unreasonable_chunk_size_falls_back_to_default(relay, inbox, chunk_size):
    data = os.urandom(VPS_CHUNK_SIZE + 10)
    s = Session(relay, inbox)
    s.peer.send_ctl(meta(size=len(data), sha=hashlib.sha256(data).hexdigest(), chunk_size=chunk_size, total_chunks=999))
    assert s.peer.recv_ctl()["type"] == "relay_meta_ack"
    s.peer.send_chunk(0, data[:VPS_CHUNK_SIZE])
    s.peer.send_chunk(1, data[VPS_CHUNK_SIZE:])
    s.peer.send_ctl({"type": "relay_done", "sha256": hashlib.sha256(data).hexdigest(), "total_chunks": 2})
    assert s.peer.recv_ctl()["verified"] is True
    assert s.finish().read_bytes() == data


def test_missing_chunks_trigger_retransmit_request(relay, inbox):
    data = os.urandom(3 * VPS_CHUNK_SIZE)
    sha = hashlib.sha256(data).hexdigest()
    parts = [data[i:i + VPS_CHUNK_SIZE] for i in range(0, len(data), VPS_CHUNK_SIZE)]
    s = Session(relay, inbox)
    s.peer.send_ctl(meta(size=len(data), sha=sha, transfer_id="t" * 32))
    s.peer.recv_ctl()
    s.peer.send_chunk(0, parts[0])
    s.peer.send_chunk(2, parts[2])                           # chunk 1 "lost"
    s.peer.send_ctl({"type": "relay_done", "sha256": sha, "total_chunks": 3})
    assert s.peer.recv_ctl() == {"type": "relay_retransmit", "missing": [1]}
    assert (inbox / "file.bin.part.resume").exists()        # progress persisted meanwhile
    s.peer.send_chunk(1, parts[1])
    s.peer.send_ctl({"type": "relay_done", "sha256": sha, "total_chunks": 3})
    assert s.peer.recv_ctl() == {"type": "relay_done_ack", "verified": True}
    assert s.finish().read_bytes() == data


def test_hash_mismatch_deletes_partial_file(relay, inbox):
    data = b"real content"
    s = Session(relay, inbox)
    s.peer.send_ctl(meta(size=len(data), sha="f" * 64))
    s.peer.recv_ctl()
    s.peer.send_chunk(0, data)
    s.peer.send_ctl({"type": "relay_done", "sha256": "f" * 64, "total_chunks": 1})
    assert s.peer.recv_ctl() == {"type": "relay_done_ack", "verified": False}
    assert s.finish() is None
    assert list(inbox.iterdir()) == []


def test_garbage_frames_are_ignored(relay, inbox):
    data = b"ok"
    sha = hashlib.sha256(data).hexdigest()
    s = Session(relay, inbox)
    s.peer.ws.send_binary(b"\x43" + os.urandom(64))         # undecryptable control frame
    s.peer.ws.send_binary(b"\x44\x00")                      # truncated data frame
    s.peer.ws.send_binary(b"\x99hello")                     # unknown frame type
    s.peer.send_ctl(meta(size=len(data), sha=sha))
    s.peer.recv_ctl()
    s.peer.send_chunk(0, data)
    s.peer.send_ctl({"type": "relay_done", "sha256": sha, "total_chunks": 1})
    assert s.peer.recv_ctl()["verified"] is True
    assert s.finish().read_bytes() == data


def test_peer_with_too_old_protocol_is_refused(relay, inbox):
    code = _code()
    log: list[str] = []
    result = []
    receiver = VPSRelayReceiver(code, inbox, on_status=log.append, on_verify=lambda c: True)
    t = threading.Thread(target=lambda: result.append(receiver.receive()), daemon=True)
    t.start()
    peer = ScriptedPeer(relay.url, code, protocol_version=0)
    peer._send_sig({"type": "pub_key", "key": "AAAA", "protocol_version": 0, "app_version": "0.1"})
    t.join(30)
    peer.close()
    assert result == [None]
    assert "relay_incompatible" in log
