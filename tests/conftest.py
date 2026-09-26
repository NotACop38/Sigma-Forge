"""Shared fixtures. Enforces the offline guarantee for every test.

Any socket connection to a non-loopback address fails the test, so "the suite
needs no network access and no API keys" is enforced rather than assumed.
Loopback stays open for the drafter's HTTP client test, which talks to a stub
server on 127.0.0.1.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

import pytest

from sigmaforge.workspace import Workspace
from tests.support import REPO_ROOT

_REAL_CONNECT = socket.socket.connect


def _loopback(address: Any) -> bool:
    if not isinstance(address, tuple):
        return False
    host = address[0]
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    def guarded_connect(sock: socket.socket, address: Any, *args: Any, **kwargs: Any) -> Any:
        if sock.family == getattr(socket, "AF_UNIX", None) or _loopback(address):
            return _REAL_CONNECT(sock, address, *args, **kwargs)
        raise RuntimeError(f"test attempted a network connection to {address!r}")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)


@pytest.fixture(autouse=True)
def _no_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SIGMA_FORGE_LLM_BASE_URL", "SIGMA_FORGE_LLM_MODEL", "SIGMA_FORGE_LLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(scope="session")
def repo() -> Workspace:
    return Workspace(REPO_ROOT)
