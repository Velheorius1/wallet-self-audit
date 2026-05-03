"""Lattice / HNP module.

Submodules:
- ``lll_pure`` — pure-Python LLL with ``fractions.Fraction`` exact
  arithmetic. Suitable for the moderate dimensions (≤ 80) that Hidden
  Number Problem (HNP) instances built from a few hundred ECDSA
  signatures produce.
- ``hnp_construct`` — build the basis matrix B for "top-bits-zero" /
  "low-bits-zero" / "constant-byte" biased-nonce hypotheses.
- ``fpylll_adapter`` — optional path through fpylll/BKZ for higher
  dimensions; never required.

The actual orchestrator that walks bias hypotheses lives in
``wallet_self_audit.nonce.lattice`` (alongside the r-collision detector)
because it consumes ``SignatureRecord``s and feeds the recovery-detector.
"""

from __future__ import annotations
