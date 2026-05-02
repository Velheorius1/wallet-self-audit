"""PRNG audit module — Milk Sad, Randstorm, brainwallet detection.

Public surface (Phase 2):

- ``bip39.entropy_to_mnemonic`` / ``bip39.mnemonic_to_entropy`` — fast pure
  reverse for the BIP-39 wordlist (no PBKDF2).
- ``derive.first_addresses`` — derive a small set of canonical receive
  addresses from a 16-byte entropy buffer.
- ``mt19937_cpp.MT19937`` — libc++/libstdc++/MSVC-compatible Mersenne Twister
  with deterministic ``seed_seq``-based seeding.
- ``milk_sad.scan_window`` — timestamp brute force against an entropy.
- ``randstorm.scan_seeds`` — V8 ``Math.random`` MWC variant brute force.
- ``brainwallet.scan_phrases`` — SHA-256 of common phrases.

The orchestrator is in ``vectors.prng_audit``. It calls these modules and
returns a ``VerdictWithoutKey``.
"""

from __future__ import annotations
