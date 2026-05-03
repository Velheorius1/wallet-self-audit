"""Nonce-audit orchestrator — r-collision detection with verdict-only output.

Pipeline:
1. ``extractor.extract_outgoing_signatures`` — fetch every spending
   signature for the user's address (BIP-322 ownership already verified
   by the CLI before this code runs).
2. ``collision.find_collisions`` — find (pubkey, r) groups with >= 2
   distinct ``(z, s)`` pairs.
3. For each collision group, project both signatures to a candidate Q
   via ``recovery_detector.collision_recovers_pubkey``. If both project
   to a known-on-chain pubkey, emit ``VULNERABLE``.

Output: ``VerdictWithoutKey``. Never returns ``d``.

Information mode: an alternative entrypoint reports only counts (number
of outgoing tx, number of collision groups), without the full pipeline.
This is the public-information mode that requires no proof-of-ownership.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass

from wallet_self_audit.crypto.recovery_detector import (
    collision_recovers_pubkey,
)
from wallet_self_audit.crypto.recovery_detector import (
    fingerprint as nonce_fingerprint,
)
from wallet_self_audit.nonce.collision import CollisionGroup, find_collisions
from wallet_self_audit.nonce.extractor import (
    MempoolClient,
    SignatureRecord,
    extract_outgoing_signatures,
)
from wallet_self_audit.nonce.lattice import LatticeHit, attempt_recovery
from wallet_self_audit.verdict import VerdictWithoutKey


@dataclass(frozen=True, slots=True)
class NonceAuditConfig:
    """Knobs for ``run_nonce_audit``."""

    address: str
    max_txs: int = 200


def _make_safe_or_suspicious_verdict(
    *,
    address: str,
    n_signatures: int,
    audit_id: str,
    also_lattice_clean: bool = False,
) -> VerdictWithoutKey:
    """Construct the clean-result verdict.

    SAFE only when there were enough signatures to make a clean result
    meaningful (>= 1). With zero signatures the wallet has never spent,
    so r-collision is undefined; we report SUSPICIOUS — partial.
    """
    checks: tuple[str, ...] = (
        ("r_collision", "lattice_bias") if also_lattice_clean else ("r_collision",)
    )
    if n_signatures == 0:
        return VerdictWithoutKey(
            address=address,
            status="SUSPICIOUS",
            finding="none",
            confidence=0.5,
            key_fingerprint=None,
            recommendation=(
                "No outgoing signatures found for this address. The "
                "r-collision check is not applicable. For a fresh-wallet "
                "audit run wsa prng-audit instead."
            ),
            evidence_refs=(),
            audit_id=audit_id,
            checks_performed=checks,
        )
    return VerdictWithoutKey(
        address=address,
        status="SAFE",
        finding="none",
        confidence=0.95,
        key_fingerprint=None,
        recommendation=(
            "No nonce reuse detected and no lattice / HNP recovery "
            "succeeded against the configured bias hypotheses. Note: "
            "absence of recovery is not a guarantee of safety against "
            "novel attack patterns."
        ),
        evidence_refs=(),
        audit_id=audit_id,
        checks_performed=checks,
    )


def _verdict_from_collision(
    *,
    address: str,
    audit_id: str,
    cg: CollisionGroup,
    pair_a: SignatureRecord,
    pair_b: SignatureRecord,
) -> VerdictWithoutKey:
    """Build the VULNERABLE verdict for a confirmed nonce reuse."""
    fp = nonce_fingerprint(
        pubkey_compressed=cg.pubkey_compressed,
        r=cg.r,
        txid_a=pair_a.txid,
        txid_b=pair_b.txid,
    )
    # evidence_refs are 64-hex txids.
    txids = (pair_a.txid, pair_b.txid)
    return VerdictWithoutKey(
        address=address,
        status="VULNERABLE",
        finding="r_collision",
        confidence=0.99,
        key_fingerprint=fp,
        recommendation=(
            "Nonce reuse detected on outgoing signatures. The private key "
            "controlling this wallet is recoverable from public chain data "
            "by anyone. Move funds to a fresh wallet IMMEDIATELY."
        ),
        evidence_refs=txids,
        audit_id=audit_id,
        checks_performed=("r_collision",),
    )


def run_nonce_audit(
    config: NonceAuditConfig,
    client: MempoolClient,
) -> VerdictWithoutKey:
    """Top-level orchestrator. The CLI verifies BIP-322 ownership first."""
    audit_id = str(uuid.uuid4())
    records = extract_outgoing_signatures(config.address, client, max_txs=config.max_txs)

    groups = find_collisions(records)

    for cg in groups:
        # Find any two distinct (z, s) records in the group and verify the
        # recovery via verify-by-pubkey-projection.
        seen: list[SignatureRecord] = []
        for rec in cg.records:
            if not any(s.z == rec.z and s.s == rec.s for s in seen):
                seen.append(rec)
            if len(seen) >= 2:
                break
        if len(seen) < 2:
            continue
        a, b = seen[0], seen[1]
        if collision_recovers_pubkey(
            r=cg.r,
            s_a=a.s,
            z_a=a.z,
            s_b=b.s,
            z_b=b.z,
            known_pubkey_compressed=cg.pubkey_compressed,
        ):
            return _verdict_from_collision(
                address=config.address,
                audit_id=audit_id,
                cg=cg,
                pair_a=a,
                pair_b=b,
            )

    # Stage B: lattice / HNP attack on biased nonces. Group sigs by pubkey
    # (most wallets reuse one pubkey across all outgoing tx) and try the
    # default hypothesis ladder. We never store candidate ``d`` values.
    lattice_hit, lattice_attempted = _stage_b_lattice(records)
    if lattice_hit is not None:
        return _verdict_from_lattice(
            address=config.address,
            audit_id=audit_id,
            hit=lattice_hit,
        )

    return _make_safe_or_suspicious_verdict(
        address=config.address,
        n_signatures=len(records),
        audit_id=audit_id,
        also_lattice_clean=lattice_attempted,
    )


def _stage_b_lattice(
    records: list[SignatureRecord],
) -> tuple[LatticeHit | None, bool]:
    """Group signatures by pubkey and try the lattice attack on each group.

    Returns:
        ``(hit_or_none, attempted)`` — ``attempted`` is True iff at least
        one pubkey-group had enough signatures for the smallest-min-sigs
        hypothesis (top_bits_zero(8) = 33 sigs). Used by callers to give
        an honest "we tried" vs "we skipped due to too few sigs" verdict.
    """
    from wallet_self_audit.lattice.hnp_construct import min_signatures_required

    min_sigs_for_smallest_hyp = min_signatures_required(8)
    attempted = False
    by_pub: dict[bytes, list[SignatureRecord]] = defaultdict(list)
    for rec in records:
        by_pub[rec.pubkey_compressed].append(rec)
    for pub, sig_list in by_pub.items():
        if len(sig_list) >= min_sigs_for_smallest_hyp:
            attempted = True
        hit = attempt_recovery(sig_list, pub)
        if hit is not None:
            return hit, True
    return None, attempted


def _verdict_from_lattice(
    *,
    address: str,
    audit_id: str,
    hit: LatticeHit,
) -> VerdictWithoutKey:
    """Build the VULNERABLE verdict for an HNP/lattice recovery."""
    return VerdictWithoutKey(
        address=address,
        status="VULNERABLE",
        finding="lattice_bias",
        confidence=0.97,
        key_fingerprint=hit.key_fingerprint,
        recommendation=(
            "Lattice / HNP attack succeeded against biased nonces. The "
            "private key controlling this wallet is recoverable from "
            "public chain data given the bias structure detected by the "
            "audit. Move funds to a fresh wallet IMMEDIATELY."
        ),
        evidence_refs=(),
        audit_id=audit_id,
        checks_performed=("r_collision", "lattice_bias"),
    )


def run_nonce_audit_informational(
    config: NonceAuditConfig,
    client: MempoolClient,
) -> dict[str, object]:
    """Public-information-only mode (no BIP-322 required).

    Returns counts and minimal evidence — never the recovered pubkey
    fingerprint. Useful for "is this address worth auditing?" prequalifiers.
    """
    records = extract_outgoing_signatures(config.address, client, max_txs=config.max_txs)
    groups = find_collisions(records)
    return {
        "address": config.address,
        "outgoing_tx_count": len(records),
        "collision_groups": len(groups),
        "informational_only": True,
    }


__all__ = [
    "NonceAuditConfig",
    "run_nonce_audit",
    "run_nonce_audit_informational",
]
