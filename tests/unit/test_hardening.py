"""Unit tests for ``hardening``.

Note: the actual auto-import hardening is bypassed in the test session
(``WSA_SKIP_HARDEN=1`` in conftest.py). These tests call the underlying
functions directly and use subprocesses where we need the real env.
"""

from __future__ import annotations

import resource
import sys

import pytest

from wallet_self_audit.hardening import (
    HardeningRefused,
    _disable_core_dumps,
    _probe_mlock,
    _refuse_unsafe_environments,
    harden_process,
)


def test_disable_core_dumps_returns_bool() -> None:
    ok = _disable_core_dumps()
    assert isinstance(ok, bool)
    if ok:
        # Verify rlimit was actually set.
        soft, _hard = resource.getrlimit(resource.RLIMIT_CORE)
        assert soft == 0


def test_probe_mlock_returns_bool() -> None:
    ok = _probe_mlock()
    assert isinstance(ok, bool)
    # We don't assert True — it's environment-dependent (Docker, restricted
    # shells, etc.). Just verify the function doesn't crash.


def test_harden_process_returns_status_dict() -> None:
    status = harden_process()
    assert isinstance(status, dict)
    assert "core_dumps_disabled" in status
    assert "mlock_available" in status


def test_refuse_jupyter_via_module_inject(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend ipykernel is loaded — should raise."""
    monkeypatch.setitem(sys.modules, "ipykernel", object())
    with pytest.raises(HardeningRefused, match="Jupyter"):
        _refuse_unsafe_environments()


def test_refuse_ipython_via_module_inject(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "IPython", object())
    with pytest.raises(HardeningRefused, match="IPython"):
        _refuse_unsafe_environments()


def test_refuse_subinterpreter_via_module_inject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "_xxsubinterpreters", object())
    with pytest.raises(HardeningRefused, match="subinterpreter"):
        _refuse_unsafe_environments()


def test_normal_environment_does_not_refuse() -> None:
    """In a clean test env, no refusal."""
    # Remove any inadvertent test infrastructure.
    # (sys.flags.interactive is read-only; we rely on conftest setup.)
    if not sys.flags.interactive and "ipykernel" not in sys.modules:
        # No exception expected.
        _refuse_unsafe_environments()
