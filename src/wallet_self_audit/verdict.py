"""``VerdictWithoutKey`` — the central output contract of wallet-self-audit.

The class is structurally incapable of carrying a 32-byte private key. This
is enforced via three layers:

1. **frozen=True** — fields cannot be mutated after construction.
2. **slots=True** — no ``__dict__``; ``object.__setattr__`` cannot inject new
   attributes silently.
3. **__post_init__ class invariant** — rejects any string field (other than
   the ``audit_id``/txid allowlist) that contains > 16 hex characters.

In addition:
- ``evidence_refs`` and ``checks_performed`` are ``tuple`` (not ``list``) so
  they cannot be mutated even on a frozen instance (frozen is shallow).
- ``checks_performed`` is **required** to kill the "false-SAFE" failure mode:
  every ``SAFE`` verdict must enumerate which checks were actually run.

See ``tests/unit/test_verdict.py`` and ``tests/property/test_verdict_invariant.py``
for the invariant test corpus.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal, NewType

# Type aliases for fields that *legitimately* contain hex characters and would
# otherwise trip the >16-hex-run invariant.
AuditId = NewType("AuditId", str)
Txid = NewType("Txid", str)
Fingerprint16 = NewType("Fingerprint16", str)


Status = Literal["SAFE", "SUSPICIOUS", "VULNERABLE"]
Finding = Literal[
    "none",
    "r_collision",
    "lattice_bias",
    "weak_prng_milksad",
    "weak_prng_randstorm",
    "brainwallet",
]


# Maximum length of a contiguous hex run allowed in any free-form text field
# (``recommendation``, ``finding``). 16 hex chars = 8 bytes, well below the
# 32-byte private-key threshold. We check a *contiguous run*, not a total
# count: natural-language recommendations contain many incidental ``a``-``f``
# letters but never a 17-char hex *run* unless something is leaking.
#
# Word boundaries (``\b``) are intentionally NOT used: any 17-char hex run
# is suspicious regardless of surrounding context. ``logging/redaction.py``
# uses ``\b[0-9a-fA-F]{64}\b`` for log-line scrubbing because there the
# downstream tool (e.g. log search) may have already trimmed punctuation;
# ``VerdictWithoutKey`` is the upstream construction-time barrier and
# rejects strictly. The two regexes are deliberately not unified.
#
# DECISIONS.md "Hex redaction regex uses non-hex anchors, NOT \b" defines
# this barrier as defense-in-depth against ACCIDENTAL leakage by our own
# code; an active attacker can split a 64-hex secret with non-hex
# separators (e.g. Unicode lookalikes) and bypass the contiguous-run check.
# That class of bypass is intentionally OUT of this barrier's scope —
# Python is not memory-safe; an attacker with code execution can always
# bypass via ``object.__setattr__`` regardless.
_MAX_HEX_RUN_IN_FREEFORM_FIELD: Final[int] = 16
_HEX_RUN_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-fA-F]{17,}")


# Allowlist of fields that ``to_public_json`` exposes. Updating this list is
# part of the contract change and requires updating the invariant tests.
_PUBLIC_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "address",
        "status",
        "finding",
        "confidence",
        "key_fingerprint",
        "recommendation",
        "evidence_refs",
        "audit_id",
        "checks_performed",
    }
)


def _has_long_hex_run(s: str) -> bool:
    """Return True iff *s* contains a contiguous hex-character run longer
    than ``_MAX_HEX_RUN_IN_FREEFORM_FIELD``.

    Used by the class invariant to catch a 32-byte (64-hex) secret leaking
    into a free-form text field, while letting natural-language strings —
    which contain many incidental ``a``-``f`` letters but no long contiguous
    hex sequence — pass through.
    """
    return _HEX_RUN_RE.search(s) is not None


def _is_lowercase_hex(s: str, length: int) -> bool:
    """Return True iff *s* is exactly *length* lowercase hex characters."""
    return len(s) == length and all(c in "0123456789abcdef" for c in s)


@dataclass(frozen=True, slots=True, kw_only=True)
class VerdictWithoutKey:
    """Audit verdict — structurally incapable of carrying a private key.

    Fields:
        address: Bitcoin address being audited (P2PKH/P2WPKH/P2SH-P2WPKH/P2WSH).
        status: One of ``SAFE``, ``SUSPICIOUS``, ``VULNERABLE``.
        finding: Specific vulnerability code, or ``none``.
        confidence: Probability the verdict is correct, in ``[0.0, 1.0]``.
        key_fingerprint: 16 lowercase hex chars OR None — *never* a full
            32-byte secret. Computed as ``sha256(d || domain_sep)[:16]`` only
            inside coincurve C; ``d`` never materializes in Python int.
        recommendation: Human-readable next step ("Move funds to a fresh
            wallet now."). Must NOT contain > 16 hex chars.
        evidence_refs: Tuple of 64-char lowercase hex txids — public chain
            references, never raw signature components (r, s, z).
        audit_id: UUID v4 string for cross-referencing audit_chain.jsonl.
        checks_performed: Tuple of vector names that ran (e.g.
            ``("milk_sad", "randstorm", "r_collision")``). REQUIRED so a
            ``SAFE`` verdict can never be unqualified.
    """

    address: str
    status: Status
    finding: Finding
    confidence: float
    key_fingerprint: str | None
    recommendation: str
    evidence_refs: tuple[str, ...]
    audit_id: str
    checks_performed: tuple[str, ...]

    def __post_init__(self) -> None:
        # 1. Confidence in valid range.
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0.0, 1.0], got {self.confidence!r}")

        # 2. key_fingerprint is exactly 16 lowercase hex chars or None.
        if self.key_fingerprint is not None and not _is_lowercase_hex(self.key_fingerprint, 16):
            raise ValueError("key_fingerprint must be exactly 16 lowercase hex chars or None")

        # 3. checks_performed required (non-empty unless explicit empty for
        #    "no checks ran" terminal-error case; allowed but flagged).
        # Runtime check is defensive — type system already constrains this,
        # but a caller passing a list via type: ignore would slip through.
        if not isinstance(self.checks_performed, tuple):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError(
                f"checks_performed must be tuple, got {type(self.checks_performed).__name__}"
            )

        # 4. evidence_refs must be tuple of 64-hex txids (or empty tuple).
        if not isinstance(self.evidence_refs, tuple):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError(f"evidence_refs must be tuple, got {type(self.evidence_refs).__name__}")
        for ref in self.evidence_refs:
            if not _is_lowercase_hex(ref, 64):
                raise ValueError(
                    f"evidence_refs entries must be 64-char lowercase hex (got {ref!r})"
                )

        # 5. Class invariant: free-form text fields must NOT contain a
        #    contiguous hex *run* longer than 16 chars. A 32-byte secret
        #    rendered as 64 contiguous hex chars is caught; natural-language
        #    recommendations like "Move funds to a freshly-generated wallet"
        #    pass even though they contain many incidental a-f letters,
        #    because there is never a 17-char unbroken hex sequence in
        #    real text. ``address`` is excluded — bech32 addresses (bc1q...)
        #    legitimately contain mixed hex-like characters that get broken
        #    by the bech32 separator and non-hex characters anyway.
        for fname in ("recommendation", "finding"):
            value = getattr(self, fname)
            if _has_long_hex_run(value):
                raise ValueError(
                    f"field {fname!r} contains a hex run longer than "
                    f"{_MAX_HEX_RUN_IN_FREEFORM_FIELD} chars (possible private key leak)"
                )

        # 6. status / finding are constrained by Literal types — runtime check
        #    for defense in depth.
        if self.status not in ("SAFE", "SUSPICIOUS", "VULNERABLE"):
            raise ValueError(f"invalid status: {self.status!r}")
        if self.finding not in (
            "none",
            "r_collision",
            "lattice_bias",
            "weak_prng_milksad",
            "weak_prng_randstorm",
            "brainwallet",
        ):
            raise ValueError(f"invalid finding: {self.finding!r}")

        # 7. Logical consistency: SAFE status must have finding=none.
        if self.status == "SAFE" and self.finding != "none":
            raise ValueError(f"status=SAFE requires finding=none, got finding={self.finding!r}")

    def to_public_json(self) -> dict[str, object]:
        """Return a dict containing exactly the allowlisted public fields.

        Use this instead of ``dataclasses.asdict()`` — explicit allowlist
        prevents future-added private fields from leaking into reports.
        """
        result: dict[str, object] = {}
        for field_name in _PUBLIC_FIELDS:
            value: object = getattr(self, field_name)
            if isinstance(value, tuple):
                result[field_name] = list(value)  # pyright: ignore[reportUnknownArgumentType]
            else:
                result[field_name] = value
        return result
