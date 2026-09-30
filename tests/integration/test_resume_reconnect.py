"""Resume after interruption and auto-reconnect after a network drop."""

import hashlib
import os
import threading

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
