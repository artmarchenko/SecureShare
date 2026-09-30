from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from app.ws_relay import VPSRelayReceiver, VPSRelaySender


def new_code() -> str:
    raw = secrets.token_hex(4)
    return f"{raw[:4]}-{raw[4:]}"


@dataclass
class Run:
    code: str
    sender: VPSRelaySender
    receiver: VPSRelayReceiver
    send_result: list = field(default_factory=list)
    recv_result: list = field(default_factory=list)
    sender_log: list = field(default_factory=list)
    receiver_log: list = field(default_factory=list)
    progress: list = field(default_factory=list)
    threads: list = field(default_factory=list)

    def start(self) -> "Run":
        self.threads = [
            threading.Thread(target=lambda: self.send_result.append(self.sender.send()), daemon=True),
            threading.Thread(target=lambda: self.recv_result.append(self.receiver.receive()), daemon=True),
        ]
        for t in self.threads:
            t.start()
        return self

    def join(self, timeout: float = 60) -> "Run":
        for t in self.threads:
            t.join(timeout)
        assert not any(t.is_alive() for t in self.threads), "transfer did not finish in time"
        return self

    @property
    def sent(self):
        return self.send_result[0]

    @property
    def received(self) -> Path | None:
        return self.recv_result[0]


@pytest.fixture
def transfer(relay, tmp_path):
    """Factory: build a sender/receiver pair for a file."""
    def _make(src: Path, save_dir: Path | None = None, code: str | None = None,
              sender_verify=lambda c: True, receiver_verify=lambda c: True) -> Run:
        code = code or new_code()
        save_dir = save_dir or (tmp_path / "inbox")
        save_dir.mkdir(exist_ok=True)
        run = Run(code=code, sender=None, receiver=None)  # type: ignore[arg-type]
        run.sender = VPSRelaySender(
            code, src,
            on_status=run.sender_log.append,
            on_verify=sender_verify,
        )
        run.receiver = VPSRelayReceiver(
            code, save_dir,
            on_status=run.receiver_log.append,
            on_progress=lambda d, t, s: run.progress.append((d, t)),
            on_verify=receiver_verify,
        )
        return run
    return _make
