"""Process hardening: core dumps off, mlock probe, refuse unsafe environments.

This module is imported by ``wallet_self_audit/__init__.py`` to harden the
process at module load. Set ``WSA_SKIP_HARDEN=1`` to skip (test fixtures only).

Hardening applied (in order):
1. Refuse Jupyter / IPython (caches ``_``, ``__``, ``___``).
2. Refuse ``python -i`` (post-mortem REPL).
3. Refuse subinterpreters (PEP 684 — share heap).
4. Disable ``tracemalloc`` and ``sys.settrace`` (heap snapshots).
5. Set ``RLIMIT_CORE = (0, 0)`` (no core dumps with memory).
6. Probe per-buffer ``mlock`` availability (graceful degrade).

Returns a status dict consumed by ``wsa doctor``.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import resource
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)

# Probe size for mlock test — 4KB is one page on all targets and always succeeds
# under default RLIMIT_MEMLOCK on macOS / Linux.
_MLOCK_PROBE_SIZE = 4096


class HardeningRefused(RuntimeError):
    """Raised when the runtime environment is unsafe and we refuse to start."""


def _refuse_unsafe_environments() -> None:
    """Raise ``HardeningRefused`` if the current environment is unsafe.

    Refused environments:
    - Jupyter / IPython (``_``, ``__``, ``___`` cache last expressions).
    - ``python -i`` interactive mode (post-mortem REPL exposes secrets).
    - Subinterpreters (PEP 684) — share heap memory.
    """
    # 1. Jupyter / IPython.
    if "ipykernel" in sys.modules:
        raise HardeningRefused(
            "Refusing to run inside Jupyter (ipykernel caches last expressions). "
            "Run from a regular terminal."
        )
    if "IPython" in sys.modules:
        raise HardeningRefused(
            "Refusing to run inside IPython (caches '_', '__', '___'). "
            "Run from a regular terminal."
        )

    # 2. python -i — interactive REPL after script ends.
    if sys.flags.interactive:
        raise HardeningRefused(
            "Refusing to run with 'python -i' (post-mortem REPL exposes "
            "process state). Run as 'python -m wallet_self_audit' or via 'wsa'."
        )

    # 3. Subinterpreters (PEP 684) — heap sharing.
    if "_xxsubinterpreters" in sys.modules or "_interpreters" in sys.modules:
        raise HardeningRefused(
            "Refusing to run under a subinterpreter (heap may be shared)."
        )


def _disable_heap_snapshotting() -> None:
    """Disable tracemalloc and clear any settrace hook."""
    try:
        import tracemalloc

        if tracemalloc.is_tracing():
            tracemalloc.stop()
    except ImportError:  # pragma: no cover
        pass

    # sys.settrace(None) clears any set tracer (debuggers, coverage tools).
    # We intentionally clear it: a tracer can capture local variables
    # including Secret contents.
    sys.settrace(None)


def _disable_core_dumps() -> bool:
    """Set RLIMIT_CORE to (0, 0). Returns True on success."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return True
    except (ValueError, OSError) as exc:
        log.warning(
            "Could not disable core dumps; an OS-level core file could "
            "contain key material if the process crashes. Reason: %s",
            exc,
        )
        return False


def _probe_mlock() -> bool:
    """Try to mlock a small probe buffer. Returns True on success.

    On macOS unprivileged mlock often works for small buffers (under
    RLIMIT_MEMLOCK default ~64KB) but mlockall typically fails. Per-buffer
    mlock is the realistic strategy.
    """
    libc_path = ctypes.util.find_library("c")
    if not libc_path:  # pragma: no cover
        log.warning("Could not locate libc; mlock probe skipped.")
        return False

    try:
        libc = ctypes.CDLL(libc_path, use_errno=True)
    except OSError as exc:  # pragma: no cover
        log.warning("Could not load libc; mlock probe skipped: %s", exc)
        return False

    # Allocate a probe buffer. Use a real bytearray so we get a real virtual
    # address (vs Python ints which may be in interned heap).
    probe = (ctypes.c_ubyte * _MLOCK_PROBE_SIZE)()
    rc = libc.mlock(ctypes.addressof(probe), _MLOCK_PROBE_SIZE)
    if rc == 0:
        # Success — unlock immediately so we don't waste lock budget.
        libc.munlock(ctypes.addressof(probe), _MLOCK_PROBE_SIZE)
        return True

    errno = ctypes.get_errno()
    log.warning(
        "mlock probe failed (errno=%d). Per-Secret mlock will not be "
        "attempted; airgap recommended for high-value audits.",
        errno,
    )
    return False


def harden_process() -> dict[str, bool]:
    """Apply all hardening steps. Returns a status dict for ``wsa doctor``.

    Side effects:
    - May raise ``HardeningRefused`` if the environment is unsafe.
    - Sets RLIMIT_CORE to (0, 0).
    - Stops tracemalloc, clears sys.settrace.
    - Probes mlock (does not actually keep anything locked).

    Returns:
        Dict with keys ``core_dumps_disabled`` and ``mlock_available``.
    """
    _refuse_unsafe_environments()
    _disable_heap_snapshotting()

    return {
        "core_dumps_disabled": _disable_core_dumps(),
        "mlock_available": _probe_mlock(),
    }
