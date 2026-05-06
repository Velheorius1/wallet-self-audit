"""JSON rendering of an audit verdict.

Wraps :py:meth:`VerdictWithoutKey.to_public_json` with stable key order
(``sort_keys=True``) and consistent indentation so reports diff cleanly.
"""

from __future__ import annotations

import json

from wallet_self_audit.verdict import VerdictWithoutKey


def render_json(verdict: VerdictWithoutKey, *, indent: int = 2) -> str:
    """Render ``verdict`` as a deterministic JSON string."""
    return json.dumps(
        verdict.to_public_json(),
        sort_keys=True,
        indent=indent,
        separators=(",", ": "),
    )


__all__ = ["render_json"]
