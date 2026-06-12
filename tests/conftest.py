"""Shared test configuration: enforce the zero-network guarantee structurally.

The README and SECURITY.md promise that tests run with zero network calls and
zero API keys. Historically that rested on individual mocks (the drafter's
``completion_fn``) and one excluded pySigma validator (``d3_fendtag``, which
fetches MITRE D3FEND data over HTTPS). This autouse fixture turns the promise
into an enforced invariant: any non-AF_UNIX socket connection attempted by any
test fails loudly. AF_UNIX stays allowed for local IPC (e.g. multiprocessing).
"""

from __future__ import annotations

import socket

import pytest

_REAL_CONNECT = socket.socket.connect


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def guarded_connect(self: socket.socket, address, *args, **kwargs):
        if getattr(socket, "AF_UNIX", None) is not None and self.family == socket.AF_UNIX:
            return _REAL_CONNECT(self, address, *args, **kwargs)
        raise RuntimeError(
            f"test attempted a network connection to {address!r}; "
            "tests must be fully offline (mock the call instead)"
        )

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
