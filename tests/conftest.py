"""Pytest fixtures and skip conditions for wallet-self-audit tests.

Notes on environment:
- ``WSA_SKIP_HARDEN=1`` is set BEFORE importing the package — pytest itself
  runs in an environment that may have tracemalloc/settrace, so we skip
  hardening to let the test runner work. Hardening is independently tested
  in ``test_hardening.py`` via subprocess invocation.
"""

from __future__ import annotations

import os

# Must be set BEFORE importing wallet_self_audit anywhere in the test session.
os.environ.setdefault("WSA_SKIP_HARDEN", "1")

import pytest


@pytest.fixture(autouse=True)
def _isolated_state_dir(tmp_path, monkeypatch):
    """Redirect XDG state to a tmp dir for each test."""
    state = tmp_path / "state"
    data = tmp_path / "data"
    config = tmp_path / "config"
    state.mkdir(parents=True)
    data.mkdir(parents=True)
    config.mkdir(parents=True)

    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    yield {"state": state, "data": data, "config": config}
