"""PRNG audit orchestrator — Milk Sad / Randstorm / Brainwallet.

Combines the three PRNG vectors into a single ``run_prng_audit`` entrypoint
that returns a :py:class:`VerdictWithoutKey`. The CLI calls this; tests
call this; it is the only public surface that `wsa prng-audit` touches.

Two input modes (mutually exclusive):
- **Entropy mode** (``MnemonicHandle``): user has the mnemonic, we derive
  entropy and run all three checks.
- **Address-only mode** (``addresses``): user knows only their receive
  address(es). We can only run Milk Sad / Randstorm / Brainwallet via
  full BIP-32 derivation per candidate (slow, but no secret required).

Output rules:
- ``VULNERABLE`` if any vector finds a match. ``finding`` is set to the
  most specific code (``weak_prng_milksad`` / ``weak_prng_randstorm`` /
  ``brainwallet``).
- ``SUSPICIOUS`` if all configured vectors completed cleanly but coverage
  is partial (e.g. Randstorm only covered the dominant V8 variant). The
  ``recommendation`` documents what was *not* covered.
- ``SAFE`` only if **all** configured vectors completed with full coverage
  and no match. ``checks_performed`` always lists which ran — a SAFE
  verdict is never unqualified.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from typing import Final, Literal

from wallet_self_audit.prng import brainwallet, milk_sad, randstorm
from wallet_self_audit.prng.owner_input import MnemonicHandle
from wallet_self_audit.verdict import (
    Finding,
    VerdictWithoutKey,
)

VectorName = Literal["milk_sad", "randstorm", "brainwallet"]

# Domain separator for ``key_fingerprint`` SHA-256 — keeps fingerprints
# from this tool from colliding with other forensic tools' fingerprints.
_FINGERPRINT_DOMAIN: Final[bytes] = b"wallet-self-audit/v1.0/prng-fingerprint"


@dataclass(frozen=True, slots=True)
class PrngAuditConfig:
    """Knobs for ``run_prng_audit``. All fields default to safe values."""

    address: str  # The address being audited (used for verdict.address)
    target_addresses: frozenset[str]  # All known addresses (incl. ``address``)
    vectors: tuple[VectorName, ...] = ("milk_sad", "randstorm", "brainwallet")
    milk_sad_window: tuple[int, int] = (
        milk_sad.MILK_SAD_WINDOW_DEFAULT_START,
        milk_sad.MILK_SAD_WINDOW_DEFAULT_END,
    )
    randstorm_s0_range: tuple[int, int] = randstorm.RANDSTORM_DEFAULT_S0_RANGE
    n_workers: int = 0  # 0 → default (P-cores)
    brainwallet_phrases: tuple[str, ...] | None = None  # None → built-in sample


def _fingerprint_from_inputs(*, finding: Finding, evidence: bytes) -> str:
    """Compute the public 16-hex fingerprint for a finding.

    Never uses the recovered private key (we don't have one). Uses
    ``finding`` + ``evidence`` (an evidence blob unique to the finding) so
    different findings on the same address get different fingerprints.
    """
    h = sha256()
    h.update(_FINGERPRINT_DOMAIN)
    h.update(b":")
    h.update(finding.encode("utf-8"))
    h.update(b":")
    h.update(evidence)
    return h.hexdigest()[:16]


def _make_verdict(
    *,
    address: str,
    status: Literal["SAFE", "SUSPICIOUS", "VULNERABLE"],
    finding: Finding,
    confidence: float,
    key_fingerprint: str | None,
    recommendation: str,
    checks_performed: tuple[str, ...],
) -> VerdictWithoutKey:
    return VerdictWithoutKey(
        address=address,
        status=status,
        finding=finding,
        confidence=confidence,
        key_fingerprint=key_fingerprint,
        recommendation=recommendation,
        evidence_refs=(),
        audit_id=str(uuid.uuid4()),
        checks_performed=checks_performed,
    )


def run_prng_audit(
    config: PrngAuditConfig,
    *,
    mnemonic_handle: MnemonicHandle | None = None,
) -> VerdictWithoutKey:
    """Run all configured PRNG vectors and synthesize a single verdict.

    Args:
        config: Audit knobs.
        mnemonic_handle: If provided, milk-sad / randstorm run in fast
            entropy-direct-compare mode. Otherwise they fall back to the
            slower address-derivation mode.

    Returns:
        :py:class:`VerdictWithoutKey` — never raises through normal paths.

    Raises:
        ``MilkSadValidationFailed`` if the mt19937 fixture validation
        fails. We refuse to scan with an unvalidated oracle.
    """
    if not config.target_addresses:
        raise ValueError("config.target_addresses must be non-empty")

    workers = None if config.n_workers == 0 else config.n_workers

    # We may need entropy bytes from the mnemonic handle, but only inside a
    # ``with`` so it gets burned. To avoid leaking through the function
    # signature, we re-extract per vector.
    def _entropy_bytes() -> bytes | None:
        if mnemonic_handle is None:
            return None
        with mnemonic_handle.entropy() as ent:
            return bytes(ent)

    target_entropy = _entropy_bytes()

    # ---- Milk Sad -------------------------------------------------------
    if "milk_sad" in config.vectors:
        # MilkSadValidationFailed propagates naturally if the mt19937
        # fixture validation fails — refuse to scan with a broken oracle.
        ms_hit = (
            milk_sad.scan_window(
                target_entropy,
                start=config.milk_sad_window[0],
                end=config.milk_sad_window[1],
                n_workers=workers,
            )
            if target_entropy is not None
            else milk_sad.scan_window_by_addresses(
                config.target_addresses,
                start=config.milk_sad_window[0],
                end=config.milk_sad_window[1],
                n_workers=workers,
            )
        )
        if ms_hit is not None:
            evidence_blob = ms_hit.timestamp.to_bytes(8, "big") + bytes.fromhex(
                ms_hit.candidate_entropy_hex
            )
            fp = _fingerprint_from_inputs(
                finding="weak_prng_milksad",
                evidence=evidence_blob,
            )
            return _make_verdict(
                address=config.address,
                status="VULNERABLE",
                finding="weak_prng_milksad",
                confidence=0.99,
                key_fingerprint=fp,
                recommendation=(
                    "Vulnerable to Milk Sad (CVE-2023-39910). Move funds to a "
                    "fresh wallet IMMEDIATELY — your key is reproducible from "
                    "a Unix timestamp."
                ),
                checks_performed=config.vectors,
            )

    # ---- Randstorm ------------------------------------------------------
    randstorm_partial_coverage = False
    if "randstorm" in config.vectors:
        rs_hit, rs_cov = (
            randstorm.scan_seeds(
                target_entropy,
                s0_range=config.randstorm_s0_range,
                n_workers=workers,
            )
            if target_entropy is not None
            else randstorm.scan_seeds_by_addresses(
                config.target_addresses,
                s0_range=config.randstorm_s0_range,
                n_workers=workers,
            )
        )
        if rs_hit is not None:
            fp = _fingerprint_from_inputs(
                finding="weak_prng_randstorm",
                evidence=rs_hit.s0_seed.to_bytes(8, "big")
                + rs_hit.s1_seed.to_bytes(8, "big"),
            )
            return _make_verdict(
                address=config.address,
                status="VULNERABLE",
                finding="weak_prng_randstorm",
                confidence=0.99,
                key_fingerprint=fp,
                recommendation=(
                    "Vulnerable to Randstorm (BitcoinJS pre-2014 V8 weakness). "
                    "Move funds to a fresh wallet IMMEDIATELY."
                ),
                checks_performed=config.vectors,
            )
        # No hit but Randstorm coverage is intrinsically partial — flag it.
        randstorm_partial_coverage = True
        _ = rs_cov  # the coverage object documents what was scanned

    # ---- Brainwallet ----------------------------------------------------
    if "brainwallet" in config.vectors:
        bw_hit = brainwallet.scan_phrases(
            config.target_addresses,
            wordlist=config.brainwallet_phrases,
            n_workers=workers,
        )
        if bw_hit is not None:
            fp = _fingerprint_from_inputs(
                finding="brainwallet",
                evidence=bw_hit.phrase_index.to_bytes(8, "big"),
            )
            return _make_verdict(
                address=config.address,
                status="VULNERABLE",
                finding="brainwallet",
                confidence=0.99,
                key_fingerprint=fp,
                recommendation=(
                    "Brainwallet detected — your key is in a public wordlist. "
                    "Move funds to a fresh wallet IMMEDIATELY."
                ),
                checks_performed=config.vectors,
            )

    # ---- Synthesise clean verdict --------------------------------------
    if randstorm_partial_coverage:
        return _make_verdict(
            address=config.address,
            status="SUSPICIOUS",
            finding="none",
            confidence=0.85,
            key_fingerprint=None,
            recommendation=(
                "No matches found across configured vectors. Coverage is "
                "partial: Randstorm scan covered V8 MWC dominant variant only "
                "(WebKit and Firefox PRNGs of the era are not in scope). For "
                "high-value wallets, see docs/threat-model.md."
            ),
            checks_performed=config.vectors,
        )

    return _make_verdict(
        address=config.address,
        status="SAFE",
        finding="none",
        confidence=0.95,
        key_fingerprint=None,
        recommendation=(
            "No matches found across configured vectors. Note: this only "
            "demonstrates resistance to the specific PRNG flaws we test for; "
            "it is not proof of overall key strength."
        ),
        checks_performed=config.vectors,
    )


def normalize_addresses(addresses: Iterable[str]) -> frozenset[str]:
    """Normalise an iterable of user-supplied addresses into a frozenset.

    Strips whitespace; rejects empty strings. Does not validate the
    address format — that is the caller's responsibility (the vectors
    silently fail to match anything for an unknown format).
    """
    out: set[str] = set()
    for a in addresses:
        s = a.strip()
        if not s:
            raise ValueError("empty address in input")
        out.add(s)
    return frozenset(out)


__all__ = [
    "PrngAuditConfig",
    "VectorName",
    "normalize_addresses",
    "run_prng_audit",
]
