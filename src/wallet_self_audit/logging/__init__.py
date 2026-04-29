"""structlog-based logging with allowlist-first redaction.

The module name is ``logging`` (shadows stdlib name only at package scope).
Import as ``from wallet_self_audit.logging import configure_logging``.
"""

from wallet_self_audit.logging.redaction import (
    ALLOWLIST_FIELDS,
    SECURITY_LEVEL,
    RedactionFailClosed,
    allowlist_filter,
    configure_logging,
    fail_closed_guard,
    suspect_hex_scrub,
)

__all__ = [
    "ALLOWLIST_FIELDS",
    "SECURITY_LEVEL",
    "RedactionFailClosed",
    "allowlist_filter",
    "configure_logging",
    "fail_closed_guard",
    "suspect_hex_scrub",
]
