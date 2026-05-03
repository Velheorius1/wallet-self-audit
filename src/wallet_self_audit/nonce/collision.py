"""r-collision detector — find duplicate r values within a single pubkey.

Given a list of :class:`SignatureRecord` from
:mod:`wallet_self_audit.nonce.extractor`, this module groups by
``(pubkey, r)`` and reports any (pubkey, r) with > 1 distinct
``(z, s)`` tuples. Those are the candidate VULNERABLE findings; the
caller passes them to
:func:`wallet_self_audit.crypto.recovery_detector.collision_recovers_pubkey`
to confirm consistency without materializing ``d``.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from wallet_self_audit.nonce.extractor import SignatureRecord


@dataclass(frozen=True, slots=True)
class CollisionGroup:
    """A group of >= 2 signatures sharing the same (pubkey, r)."""

    pubkey_compressed: bytes
    r: int
    records: tuple[SignatureRecord, ...]

    def is_real_collision(self) -> bool:
        """True iff at least two distinct (z, s) pairs share the (pubkey, r).

        A duplicate of *exactly* the same (z, s, r) is the *same* signature
        appearing twice (e.g. malleated) and is not a recovery vector.
        """
        zs_pairs = {(rec.z, rec.s) for rec in self.records}
        return len(zs_pairs) >= 2


def find_collisions(records: list[SignatureRecord]) -> list[CollisionGroup]:
    """Return all (pubkey, r) groups with at least one real collision.

    Real means: at least two records in the group differ in (z, s). A
    pair where r matches but (z, s) is identical is the same on-chain
    signature (e.g. fetched twice); we exclude those.
    """
    grouped: dict[tuple[bytes, int], list[SignatureRecord]] = defaultdict(list)
    for rec in records:
        grouped[(rec.pubkey_compressed, rec.r)].append(rec)

    out: list[CollisionGroup] = []
    for (pk, r), group in grouped.items():
        cg = CollisionGroup(pubkey_compressed=pk, r=r, records=tuple(group))
        if cg.is_real_collision():
            out.append(cg)
    return out


__all__ = ["CollisionGroup", "find_collisions"]
