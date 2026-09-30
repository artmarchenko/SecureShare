import hashlib
import os
import threading
import time

import pytest

from app.config import VPS_CHUNK_SIZE


def _sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.mark.parametrize("size", [
    1,
    VPS_CHUNK_SIZE - 1,
    VPS_CHUNK_SIZE,
    VPS_CHUNK_SIZE + 1,
    5 * 1024 * 1024 + 123,
], ids=["1B", "chunk-1", "chunk", "chunk+1", "5MB"])
def test_file_arrives_intact(transfer, tmp_path, size):
    src = tmp_path / f"payload-{size}.bin"
    src.write_bytes(os.urandom(size))
    run = transfer(src).start().join()
    assert run.sent is True
    assert run.received is not None and run.received.name == src.name
    assert _sha(run.received) == _sha(src)
    leftovers = [p.name for p in run.received.parent.iterdir() if p.name != src.name]
    assert leftovers == []  # no .part / .resume left behind


def test_compressible_file(transfer, tmp_path):
    src = tmp_path / "zeros.bin"
    src.write_bytes(b"\x00" * (3 * VPS_CHUNK_SIZE))
    run = transfer(src).start().join()
    assert run.received.read_bytes() == src.read_bytes()


def test_progress_reaches_total(transfer, tmp_path):
    src = tmp_path / "p.bin"
    src.write_bytes(os.urandom(4 * VPS_CHUNK_SIZE))
    run = transfer(src).start().join()
    assert run.received is not None
    assert all(done <= total for done, total in run.progress)


def test_empty_file_is_rejected_by_receiver(transfer, tmp_path):
    # Characterisation: zero-byte files are refused (file_size <= 0 check).
    src = tmp_path / "empty.txt"
    src.write_bytes(b"")
    run = transfer(src).start()
    run.threads[1].join(30)
    assert not run.threads[1].is_alive()
    assert run.received is None
    run.sender.cancel()
    run.join(timeout=10)
    assert run.sent is False


def test_cancel_is_prompt_while_waiting_for_meta_ack(transfer, tmp_path):
    src = tmp_path / "empty.txt"
    src.write_bytes(b"")          # receiver refuses it, so the sender waits for an ACK forever
    run = transfer(src).start()
    run.threads[1].join(30)
    time.sleep(1)
    run.sender.cancel()
    run.threads[0].join(5)
    assert not run.threads[0].is_alive()


def test_receiver_rejects_verification(transfer, tmp_path):
    src = tmp_path / "x.bin"
    src.write_bytes(os.urandom(1000))
    run = transfer(src, receiver_verify=lambda c: False).start().join()
    assert run.sent is False
    assert run.received is None
    assert not (tmp_path / "inbox" / "x.bin").exists()


def test_both_sides_see_same_verification_code(transfer, tmp_path):
    seen = {}
    src = tmp_path / "x.bin"
    src.write_bytes(b"hello")
    run = transfer(
        src,
        sender_verify=lambda c: seen.setdefault("s", c) is not None,
        receiver_verify=lambda c: seen.setdefault("r", c) is not None,
    ).start().join()
    assert run.received is not None
    assert seen["s"] == seen["r"]


def test_cancel_mid_transfer_keeps_resume_state(transfer, tmp_path, slow_sender):
    src = tmp_path / "big.bin"
    src.write_bytes(os.urandom(40 * VPS_CHUNK_SIZE))
    run = transfer(src)
    gate = threading.Event()
    original = run.receiver.on_progress

    def progress(d, t, s):
        original(d, t, s)
        if d > 5 * VPS_CHUNK_SIZE:
            gate.set()
    run.receiver.on_progress = progress
    run.start()
    assert gate.wait(30)
    run.receiver.cancel()
    run.sender.cancel()
    t0 = time.monotonic()
    run.join(timeout=30)
    assert time.monotonic() - t0 < 15
    inbox = tmp_path / "inbox"
    assert run.received is None
    assert (inbox / "big.bin.part").exists()
    assert (inbox / "big.bin.part.resume").exists()


def test_existing_file_is_kept_and_new_one_renamed(transfer, tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "doc.txt").write_bytes(b"precious original")
    (inbox / "doc (1).txt").write_bytes(b"older copy")
    src = tmp_path / "doc.txt"
    src.write_bytes(b"new content")
    run = transfer(src, save_dir=inbox).start().join()
    assert (inbox / "doc.txt").read_bytes() == b"precious original"
    assert (inbox / "doc (1).txt").read_bytes() == b"older copy"
    assert run.received == inbox / "doc (2).txt"
    assert run.received.read_bytes() == b"new content"
    assert "relay_file_renamed" in run.receiver_log


def test_rooms_are_cleaned_up(transfer, tmp_path, relay):
    src = tmp_path / "x.bin"
    src.write_bytes(b"abc")
    transfer(src).start().join()
    deadline = time.monotonic() + 5
    while relay.active_rooms() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert relay.active_rooms() == 0
