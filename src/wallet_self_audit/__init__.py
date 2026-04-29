"""wallet-self-audit — local Bitcoin wallet self-audit CLI.

Defensive by construction: returns a verdict, never outputs private keys.

On import, this module calls ``hardening.harden_process()`` which:
- Disables core dumps.
- Refuses to run in Jupyter / IPython / ``python -i`` / subinterpreters.
- Probes ``mlock`` availability (graceful degradation).
- Disables ``tracemalloc`` and ``sys.settrace``.

To skip hardening (NOT recommended; tests only), set ``WSA_SKIP_HARDEN=1``
before import.
"""

from __future__ import annotations

import os

__version__ = "1.0.0"


def _initial_harden_status() -> dict[str, bool]:
    """Return the hardening status, applying hardening unless WSA_SKIP_HARDEN is set."""
    if os.environ.get("WSA_SKIP_HARDEN"):  # pragma: no cover
        return {"core_dumps_disabled": False, "mlock_available": False, "skipped": True}
    from wallet_self_audit.hardening import harden_process

    return harden_process()


# Auto-harden on import unless explicitly skipped (test fixtures may need this).
_HARDEN_STATUS: dict[str, bool] = _initial_harden_status()


__all__ = ["__version__"]
