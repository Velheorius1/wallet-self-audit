"""Unit tests for ``Secret`` — ephemeral byte container."""

from __future__ import annotations

import copy
import pickle

import pytest

from wallet_self_audit.crypto.secret import Secret


def test_secret_constructs_with_correct_size() -> None:
    s = Secret(32)
    assert len(s.view()) == 32
    s.burn()


def test_secret_rejects_zero_or_negative_size() -> None:
    with pytest.raises(ValueError):
        Secret(0)
    with pytest.raises(ValueError):
        Secret(-1)


def test_secret_view_writes_visible() -> None:
    s = Secret(4)
    s.view()[:] = b"\x01\x02\x03\x04"
    assert bytes(s.view()) == b"\x01\x02\x03\x04"
    s.burn()


def test_burn_zeroes_buffer() -> None:
    s = Secret(8)
    s.view()[:] = b"\xff" * 8
    s.burn()
    # After burn, view() raises — verify via accessing internal _buf via slot.
    assert s._burned is True
    # The underlying bytearray is zero.
    assert bytes(s._buf) == b"\x00" * 8


def test_burn_is_idempotent() -> None:
    s = Secret(8)
    s.burn()
    s.burn()  # no exception
    assert s._burned is True


def test_view_after_burn_raises() -> None:
    s = Secret(8)
    s.burn()
    with pytest.raises(RuntimeError, match="burned"):
        s.view()


def test_context_manager_burns_on_exit() -> None:
    with Secret(16) as s:
        s.view()[:] = b"\x42" * 16
        assert s._burned is False
    assert s._burned is True


def test_context_manager_burns_on_exception() -> None:
    """Exception in with-block still burns the secret."""
    s = Secret(16)
    s.view()[:] = b"\x42" * 16
    try:
        with s:
            raise RuntimeError("simulated")
    except RuntimeError:
        pass
    assert s._burned is True


def test_repr_does_not_contain_buffer_contents() -> None:
    s = Secret(32)
    s.view()[:] = b"\xde\xad\xbe\xef" * 8
    r = repr(s)
    # Should be metadata only.
    assert "deadbeef" not in r
    assert "32" in r
    assert "burned=False" in r
    s.burn()


def test_pickle_raises() -> None:
    s = Secret(32)
    with pytest.raises(TypeError, match="cannot be pickled"):
        pickle.dumps(s)
    s.burn()


def test_deepcopy_raises() -> None:
    s = Secret(32)
    with pytest.raises(TypeError, match="cannot be deepcopied"):
        copy.deepcopy(s)
    s.burn()


def test_copy_raises() -> None:
    s = Secret(32)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(s)
    s.burn()


def test_hash_disabled() -> None:
    """__hash__ = None means Secret is unhashable (no caching side channel)."""
    s = Secret(32)
    with pytest.raises(TypeError, match="unhashable"):
        hash(s)
    s.burn()


def test_no_dict_attribute() -> None:
    """slots=True style — no __dict__."""
    s = Secret(32)
    with pytest.raises(AttributeError):
        _ = s.__dict__  # type: ignore[attr-defined]
    s.burn()
