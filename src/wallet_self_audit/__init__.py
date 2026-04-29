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

# Auto-harden on import unless explicitly skipped (test fixtures may need this).
if not os.environ.get("WSA_SKIP_HARDEN"):
    from wallet_self_audit.hardening import harden_process

    _HARDEN_STATUS = harden_process()
else:  # pragma: no cover
    _HARDEN_STATUS = {"core_dumps_disabled": False, "mlock_available": False, "skipped": True}


__all__ = ["__version__"]
