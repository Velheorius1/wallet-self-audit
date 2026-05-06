"""Audit-result renderers (txt / json / md).

Each renderer takes a :class:`VerdictWithoutKey` and produces a string
representation suitable for that medium. Renderers MUST NOT introduce
any new fields beyond what the verdict's allowlist already exposes.
"""

from __future__ import annotations
