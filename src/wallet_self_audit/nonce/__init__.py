"""Nonce-audit submodules.

- ``extractor``: fetch outgoing transactions for an address from a public
  block explorer (mempool.space) and parse the (r, s, pubkey, z) tuples.
- ``collision``: detect r-collisions among the parsed signatures.

The ECDSA math (sighash + recovery-by-projection) lives in
``wallet_self_audit.crypto.{sighash,recovery_detector}`` so it stays
network-free and unit-testable.
"""

from __future__ import annotations
