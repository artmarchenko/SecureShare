"""Resume after interruption and auto-reconnect after a network drop."""

import hashlib
import os
import socket
import threading

import pytest

from app.config import VPS_CHUNK_SIZE

CHUNKS = 40


def _big_file(tmp_path, name="big.bin"):
    src = tmp_path / name
    src.write_bytes(os.urandom(CHUNKS * VPS_CHUNK_SIZE + 777))
    return src


def _stop_after(run, fraction: float) -> threading.Event:
    """Return an event that fires once the receiver has passed `fraction`."""
    gate = threading.Event()
    original = run.receiver.on_progress

    def progress(done, total, speed):
        original(done, total, speed)
        if done >= total * fraction:
            gate.set()
    run.receiver.on_progress = progress
    return gate


def test_resume_skips_already_received_chunks(transfer, tmp_path, slow_sender):
    src = _big_file(tmp_path)

    first = transfer(src)
    gate = _stop_after(first, 0.4)
    first.start()
    assert gate.wait(30)
    first.receiver.cancel()
    first.sender.cancel()
    first.join(30)
    assert (tmp_path / "inbox" / "big.bin.part.resume").exists()

    second = transfer(src).start().join()   # new session code, same file
    assert second.received is not None
    assert hashlib.sha256(second.received.read_bytes()).digest() == hashlib.sha256(src.read_bytes()).digest()
    assert "relay_resume_found" in second.receiver_log
    assert "relay_sending_resume" in second.sender_log
    first_progress = second.progress[0][0]
    assert first_progress > 0.3 * src.stat().st_size   # progress starts from the resumed offset
    assert not (tmp_path / "inbox" / "big.bin.part.resume").exists()


def test_resume_ignored_for_different_file_with_same_name(transfer, tmp_path, slow_sender):
    src = _big_file(tmp_path)
    first = transfer(src)
    gate = _stop_after(first, 0.3)
    first.start()
    assert gate.wait(30)
    first.receiver.cancel()
    first.sender.cancel()
    first.join(30)

    src.write_bytes(os.urandom(CHUNKS * VPS_CHUNK_SIZE))   # same name, new content
    second = transfer(src).start().join()
    assert second.received.read_bytes() == src.read_bytes()
    assert "relay_resume_found" not in second.receiver_log


def test_auto_reconnect_after_network_drop(transfer, tmp_path, relay, slow_sender):
    src = _big_file(tmp_path)
    verify_calls = []

    def verify(code):
        verify_calls.append(code)
        return True

    run = transfer(src, sender_verify=verify, receiver_verify=verify)
    gate = _stop_after(run, 0.3)
    run.start()
    assert gate.wait(30)
    assert relay.drop_all_connections() >= 1
    run.join(timeout=90)

    assert run.sent is True
    assert run.received is not None
    assert run.received.read_bytes() == src.read_bytes()
    # The user confirmed the code once per side; the reconnect was auto-verified.
    assert len(verify_calls) == 2
    assert "relay_auto_verify_ok" in run.receiver_log
    assert "relay_auto_verify_ok" in run.sender_log


def test_long_transfer_is_not_cut_by_room_timeout(transfer, tmp_path, relay, slow_sender, monkeypatch):
    """ROOM_TIMEOUT is about idle rooms: a transfer that keeps relaying data
    must not be cut when it lasts longer than that (was: 30 min after the
    room was created, every long transfer was interrupted)."""
    monkeypatch.setattr(relay.relay_mod, "ROOM_TIMEOUT", 0.5)
    src = _big_file(tmp_path)   # ~1.2 s of relaying with the slow sender
    run = transfer(src).start()
    finished = threading.Event()

    def sweeper():
        while not finished.is_set():
            relay.close_stale_rooms()
            finished.wait(0.1)
    t = threading.Thread(target=sweeper, daemon=True)
    t.start()
    try:
        run.join(timeout=60)
    finally:
        finished.set()
        t.join(5)

    assert run.received.read_bytes() == src.read_bytes()
    assert "relay_connection_lost" not in run.sender_log
    assert "relay_connection_lost" not in run.receiver_log


def test_idle_room_times_out_cleanly(relay, monkeypatch):
    import time
    import websocket
    monkeypatch.setattr(relay.relay_mod, "ROOM_TIMEOUT", 0.2)
    ws = websocket.create_connection(relay.url, timeout=5)
    ws.send("idle-room-" + os.urandom(4).hex())   # waits for a peer that never comes
    deadline = time.monotonic() + 5
    while not relay.server._rooms and time.monotonic() < deadline:
        time.sleep(0.02)
    time.sleep(0.3)

    assert relay.close_stale_rooms() == 1
    assert relay.server._rooms == {}
    assert relay.server._room_seen == {}
    assert relay.server._stats_basic["active_rooms"] == 0
    try:
        ws.recv()          # the relay's close frame
    except websocket.WebSocketConnectionClosedException:
        pass
    assert not ws.connected
    ws.close()


@pytest.mark.parametrize("side", ["sender", "receiver"])
def test_auto_reconnect_when_only_one_side_drops(transfer, tmp_path, relay, slow_sender, side):
    """Only one peer loses its connection (the case seen in production on
    2026-11-25): the relay must close the other peer too, so that both sides
    reconnect into a fresh room instead of the survivor waiting forever."""
    src = _big_file(tmp_path)
    run = transfer(src)
    gate = _stop_after(run, 0.3)
    run.start()
    assert gate.wait(30)

    peer = run.sender if side == "sender" else run.receiver
    peer._ws.sock.shutdown(socket.SHUT_RDWR)    # this side's network dies
    run.join(timeout=90)

    assert run.sent is True
    assert run.received is not None
    assert run.received.read_bytes() == src.read_bytes()
    assert "relay_auto_verify_ok" in run.receiver_log
    assert "relay_auto_verify_ok" in run.sender_log
