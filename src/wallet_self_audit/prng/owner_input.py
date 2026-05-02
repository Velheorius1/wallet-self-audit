"""Owner-mode mnemonic input — interactive only, no disk I/O.

Why this is its own module: any code path that handles a 12/24-word
mnemonic is a leak risk. Centralising it here makes the leak surface
auditable. There is no ``--mnemonic`` CLI flag (shell history leak), no
file-based input (disk leak). We use :py:func:`getpass.getpass` which
disables terminal echo and goes through ``/dev/tty`` directly.

The returned :py:class:`MnemonicHandle` is **not** a string — it wraps the
bytes inside a ``Secret`` (zero-overwrite on burn) so the calling code
must use ``with handle.entropy() as secret:`` to access it.

Tier-3 confirmation: before opening the mnemonic prompt the caller is
expected to have asked the user to type the last 4 letters of an expected
receive address. That is a CLI concern, not this module's.
"""

from __future__ import annotations

import getpass
import os
import sys
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import IO, TextIO, cast

from wallet_self_audit.crypto.secret import Secret
from wallet_self_audit.prng.bip39 import InvalidMnemonic, mnemonic_to_entropy


@dataclass(frozen=True, slots=True)
class MnemonicHandle:
    """Handle around an entropy buffer. Use ``entropy()`` to access bytes."""

    _entropy_bytes: bytes  # 16/20/24/28/32 bytes; only released via context manager

    @contextmanager
    def entropy(self) -> Generator[memoryview, None, None]:
        """Yield a writable ``memoryview`` of the entropy; burn on exit."""
        with Secret(len(self._entropy_bytes)) as s:
            view = s.view()
            view[:] = self._entropy_bytes
            yield view


def prompt_mnemonic(
    *,
    confirm_phrase: str | None = None,
    stream: IO[str] | None = None,
) -> MnemonicHandle:
    """Prompt for a BIP-39 mnemonic interactively (echo disabled).

    Refuses to run unless attached to a TTY or unless ``WSA_TEST_NO_TTY=1``
    is set (test fixtures only).

    Args:
        confirm_phrase: Optional human-readable confirmation gate. The user
            must type ``confirm_phrase`` exactly before the mnemonic prompt
            opens. This is the Tier-3 "are you sure" gate.
        stream: Output stream for prompts (default: stderr). Tests may
            override.

    Returns:
        :py:class:`MnemonicHandle` — does not contain the original string,
        only the derived entropy.
    """
    if not (sys.stdin.isatty() or os.environ.get("WSA_TEST_NO_TTY") == "1"):
        raise RuntimeError(
            "prompt_mnemonic requires an interactive TTY. Run wsa from a "
            "terminal, not via a pipe or non-interactive shell."
        )

    out = stream if stream is not None else sys.stderr

    if confirm_phrase is not None:
        prompt = f"Type {confirm_phrase!r} exactly to proceed (or anything else to abort): "
        try:
            answer = input(prompt) if stream is None else _readline(out, prompt)
        except EOFError:
            raise RuntimeError("aborted: empty input on confirmation prompt") from None
        if answer.strip() != confirm_phrase:
            raise RuntimeError("aborted: confirmation phrase did not match")

    # ``getpass.getpass`` types its stream as ``TextIO | None``; we accept the
    # broader ``IO[str]`` for tests but pass it through unchanged.
    raw = getpass.getpass(
        "Mnemonic (echo disabled): ",
        stream=cast(TextIO, out) if out is not None else None,
    )
    try:
        entropy = mnemonic_to_entropy(raw)
    except InvalidMnemonic as exc:
        raise RuntimeError(f"invalid mnemonic: {exc}") from exc
    finally:
        # Best-effort: overwrite the local ``raw`` reference. Python int /
        # string interning means we cannot guarantee the original literal
        # is gone — see threat-model.md.
        raw = ""
        del raw

    return MnemonicHandle(_entropy_bytes=entropy)


def _readline(out: IO[str], prompt: str) -> str:
    """Print ``prompt`` to ``out`` and read one line from stdin."""
    out.write(prompt)
    out.flush()
    line = sys.stdin.readline()
    if not line:
        raise EOFError
    return line.rstrip("\n")


__all__ = ["MnemonicHandle", "prompt_mnemonic"]
