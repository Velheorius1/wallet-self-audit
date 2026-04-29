"""Allowlist-first redaction processor for structlog.

Processor pipeline (configured via ``configure_logging()``):

1. ``contextvars.merge_contextvars`` — merge request-scoped context.
2. ``add_log_level`` — add the level name.
3. ``TimeStamper(fmt="iso")`` — UTC ISO timestamp.
4. **``allowlist_filter``** — drop any field NOT in ``ALLOWLIST_FIELDS``.
5. **``suspect_hex_scrub``** — scan remaining string values for suspect hex.
6. **``fail_closed_guard``** — raise if anything still looks like a key.
7. ``JSONRenderer()`` — final serialization.

Why allowlist-first: blocklist alone is incomplete (we can't enumerate every
way a privkey might appear). Allowlist drops everything by default; only
explicitly-known-safe fields survive.

Why fail-closed last: if a value passes both filters but still matches a
suspect pattern, something has gone wrong. We refuse to log rather than risk
emitting a leaked secret.

Reference: deeper truth from pyca/cryptography — they don't log secrets at
all. This is belt-and-braces, not the primary defense.
"""

from __future__ import annotations

import logging
import re
from collections.abc import MutableMapping
from typing import Final

import structlog

# Custom log level for security-relevant events (between WARNING=30 and ERROR=40).
SECURITY_LEVEL: Final[int] = 35
logging.addLevelName(SECURITY_LEVEL, "SECURITY")


# ---------------------------------------------------------------------------
# Allowlist of fields that are safe to log. Updating this list is part of the
# logging contract. Any new field must be reviewed for leakage potential.
# ---------------------------------------------------------------------------
ALLOWLIST_FIELDS: Final[frozenset[str]] = frozenset(
    {
        # Event metadata
        "event",
        "level",
        "timestamp",
        "logger",
        # Audit identifiers (public)
        "address",
        "txid",
        "audit_id",
        "vector",
        "stage",
        "status",
        "finding",
        "severity",
        # Counters / timings
        "count",
        "duration_ms",
        "elapsed_ms",
        "iteration",
        "n_workers",
        "rate_qps",
        # Diagnostic (no secret content)
        "py_version",
        "platform",
        "errno",
        "reason",
        "hint",
        "exc_type",
        # Public hex prefixes (intentionally short)
        "r_prefix",  # first 6 hex chars of r-value, public-safe
        # Verdict result fields (already pass VerdictWithoutKey invariants)
        "confidence",
        "key_fingerprint",  # 16-hex by contract — see verdict.py
        "recommendation",
        "checks_performed",
    }
)


# ---------------------------------------------------------------------------
# Suspect patterns. Pre-compiled at module load; modules are imported once.
# ---------------------------------------------------------------------------
SUSPECT_HEX_64 = re.compile(r"\b[0-9a-fA-F]{64}\b")
SUSPECT_HEX_LONG = re.compile(r"\b[0-9a-fA-F]{128,}\b")
# 12-24 lowercase BIP-39-style words (heuristic — full validation would
# require the wordlist; this catches the obvious cases).
SUSPECT_BIP39 = re.compile(r"\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b")
# WIF private keys (Base58Check) — 51-52 chars, starts K/L/5.
SUSPECT_WIF = re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")
# xprv extended private keys.
SUSPECT_XPRV = re.compile(r"\b(?:xprv|yprv|zprv|tprv)[1-9A-HJ-NP-Za-km-z]{107,108}\b")


class RedactionFailClosed(RuntimeError):
    """Raised by ``fail_closed_guard`` when a suspect pattern survives filtering.

    This is intentionally fatal: better to crash than emit a leaked secret.
    Catch only at the outermost CLI boundary if you absolutely must continue.
    """


# ---------------------------------------------------------------------------
# Processors. Each takes (logger, method_name, event_dict) and returns the
# (possibly modified) event_dict. Returning a dict missing keys is fine.
# ---------------------------------------------------------------------------


def allowlist_filter(
    _logger: object, _method: str, event_dict: MutableMapping[str, object]
) -> MutableMapping[str, object]:
    """Drop any field not in ``ALLOWLIST_FIELDS``."""
    return {k: v for k, v in event_dict.items() if k in ALLOWLIST_FIELDS}


def suspect_hex_scrub(
    _logger: object, _method: str, event_dict: MutableMapping[str, object]
) -> MutableMapping[str, object]:
    """Replace suspect hex/key-like patterns inside string values with [REDACTED].

    Non-string values are passed through unchanged. Values that are entirely
    suspect get replaced; substrings inside longer text get the pattern
    replaced with ``[REDACTED]``.
    """
    redacted: dict[str, object] = {}
    for k, v in event_dict.items():
        if isinstance(v, str):
            new_v = SUSPECT_HEX_LONG.sub("[REDACTED:LONG-HEX]", v)
            # 64-hex: ONLY redact if the field name doesn't legitimately
            # contain 64-hex (e.g. ``txid``, evidence_refs). For the allowlist
            # we already dropped most fields; remaining fields like ``address``
            # never have 64-hex.
            if k not in ("txid", "evidence_refs", "audit_id"):
                new_v = SUSPECT_HEX_64.sub("[REDACTED:HEX64]", new_v)
            new_v = SUSPECT_BIP39.sub("[REDACTED:BIP39]", new_v)
            new_v = SUSPECT_WIF.sub("[REDACTED:WIF]", new_v)
            new_v = SUSPECT_XPRV.sub("[REDACTED:XPRV]", new_v)
            redacted[k] = new_v
        else:
            redacted[k] = v
    return redacted


def fail_closed_guard(
    _logger: object, _method: str, event_dict: MutableMapping[str, object]
) -> MutableMapping[str, object]:
    """Final defense: raise if ANYTHING in the event_dict still matches a
    suspect pattern after the allowlist + scrub.

    This catches structurally-novel leak paths (e.g. a new field that wasn't
    yet added to the allowlist + accidentally contained a key).
    """
    blob_parts: list[str] = []
    for v in event_dict.values():
        if isinstance(v, str):
            blob_parts.append(v)
        elif isinstance(v, (list, tuple)):
            for item in v:  # pyright: ignore[reportUnknownVariableType]
                blob_parts.append(str(item))  # pyright: ignore[reportUnknownArgumentType]
    blob = " ".join(blob_parts)

    # 64-hex check: skip if we're dealing with allowlisted hex-bearing fields
    # (txid, audit_id) — those legitimately contain 64-hex. We instead check
    # bip39, wif, xprv, long-hex which are never legitimate.
    if SUSPECT_HEX_LONG.search(blob):
        raise RedactionFailClosed("fail_closed_guard: 128+ char hex string survived filtering")
    if SUSPECT_BIP39.search(blob):
        raise RedactionFailClosed("fail_closed_guard: BIP-39 mnemonic pattern survived filtering")
    if SUSPECT_WIF.search(blob):
        raise RedactionFailClosed("fail_closed_guard: WIF private key pattern survived filtering")
    if SUSPECT_XPRV.search(blob):
        raise RedactionFailClosed("fail_closed_guard: xprv extended private key survived filtering")
    return event_dict


# ---------------------------------------------------------------------------
# Configure structlog with the redaction pipeline.
# ---------------------------------------------------------------------------
def configure_logging(level: int = logging.INFO) -> None:
    """Configure structlog with allowlist-first redaction.

    Call once at process start (typically from ``cli.py``). Subsequent calls
    overwrite the configuration.
    """
    logging.basicConfig(level=level, format="%(message)s")

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            allowlist_filter,
            suspect_hex_scrub,
            fail_closed_guard,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
