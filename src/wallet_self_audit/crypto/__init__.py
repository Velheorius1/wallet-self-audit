"""Crypto primitives: Secret wrapper, DER parser, recovery detector.

These modules deliberately avoid touching ``coincurve`` or ``btclib`` until
needed — keeps Phase 1 imports clean.
"""

from wallet_self_audit.crypto.secret import Secret

__all__ = ["Secret"]
