"""Audit vectors — one module per detection family.

Phase 2 vectors:
- ``prng_audit``: Milk Sad / Randstorm / Brainwallet.

Phase 3 will add ``nonce_audit`` (r-collision + lattice).
Phase 5 will refactor these into a registry/plugin architecture.
"""

from __future__ import annotations
