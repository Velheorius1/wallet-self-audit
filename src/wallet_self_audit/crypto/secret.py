"""``Secret`` — ephemeral byte container with explicit zero-overwrite.

Why this exists, and what it can/can't do:
- ``bytearray.__del__`` is unreliable for zeroization in CPython 3.11/3.13
  due to small-allocator free lists, ``repr()`` interning, tracemalloc, GC
  compaction, and GIL release in C extensions.
- This wrapper makes zeroization **deterministic in timing** — ``ctypes.memset``
  zeroes the buffer at a known point (``__exit__`` or ``burn()``).
- Pure Python cannot defeat a motivated attacker with host access. The real
  defense is airgap + mlock + no-core-dumps + this Secret class together.

See ``docs/threat-model.md`` for honest limitations.

Usage:
    with Secret(32) as s:
        s.view()[:] = b"...32 bytes..."
        result = some_crypto(s.view())
    # s is burned (zeroed) here.
"""

from __future__ import annotations

import ctypes
import gc
from types import TracebackType
from typing import NoReturn, SupportsIndex


class Secret:
    """One-shot mutable byte container. Use ONLY inside ``with`` blocks.

    Properties:
        - ``view()`` returns a ``memoryview`` (no copy). Caller must not let
          the view escape the ``with`` block.
        - ``burn()`` is idempotent and called automatically by ``__exit__``.
        - ``__hash__ = None`` — no hash caching as a side channel.
        - ``__reduce__`` raises — cannot be pickled.
        - ``__deepcopy__`` raises — cannot be propagated by ``copy.deepcopy``.
        - ``__repr__`` shows metadata only — never bytes.
    """

    __slots__ = ("_addr", "_buf", "_burned", "_n")

    # No-hash: prevents Python's optional caching of hash values.
    __hash__ = None  # type: ignore[assignment]

    def __init__(self, n: int) -> None:
        if not isinstance(n, int) or n <= 0:  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ValueError(f"Secret size must be a positive int, got {n!r}")
        self._n = n
        self._buf = bytearray(n)
        # ctypes array view onto the bytearray — same memory, allows memset.
        self._addr = (ctypes.c_ubyte * n).from_buffer(self._buf)
        self._burned = False

    def view(self) -> memoryview:
        """Return a writable ``memoryview`` of the buffer.

        Raises:
            RuntimeError: if the secret has already been burned.
        """
        if self._burned:
            raise RuntimeError("Secret has been burned; cannot access view()")
        return memoryview(self._buf)

    def burn(self) -> None:
        """Zero the buffer and mark as burned. Idempotent."""
        if self._burned:
            return
        # ctypes.memset writes through to the bytearray's underlying memory.
        ctypes.memset(ctypes.addressof(self._addr), 0, self._n)
        self._burned = True

    def __enter__(self) -> Secret:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.burn()
        # gc.collect() flushes circular refs (numpy arrays, coincurve C
        # extensions can hold references past obvious lifetime).
        gc.collect()

    def __repr__(self) -> str:
        # NEVER include buffer contents. This must be safe to log.
        return f"<Secret n={self._n} burned={self._burned}>"

    # Pickling would serialize the buffer to disk — refuse.
    def __reduce__(self) -> NoReturn:
        raise TypeError("Secret cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("Secret cannot be pickled")

    # deepcopy would propagate the secret — refuse. Shallow copy is also
    # refused; if you need to "share" a secret, you're doing it wrong.
    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        raise TypeError("Secret cannot be deepcopied")

    def __copy__(self) -> NoReturn:
        raise TypeError("Secret cannot be copied")
