"""Concrete vector plugins — thin adapters over ``run_prng_audit`` and
``run_nonce_audit``. Phase 5 keeps both surfaces (orchestrator function
and plugin class) callable; Phase 7 will deprecate the function form
once we have a single ``wsa audit`` entrypoint that drives plugins.
"""

from __future__ import annotations

from typing import cast

from wallet_self_audit.nonce.extractor import HttpMempoolClient, MempoolClient
from wallet_self_audit.prng.owner_input import MnemonicHandle as MnemonicHandleT
from wallet_self_audit.vectors.base import AuditContext, Stage, VectorPlugin
from wallet_self_audit.vectors.nonce_audit import (
    NonceAuditConfig,
    run_nonce_audit,
)
from wallet_self_audit.vectors.prng_audit import (
    PrngAuditConfig,
    run_prng_audit,
)
from wallet_self_audit.vectors.prng_audit import (
    VectorName as PrngVectorName,
)
from wallet_self_audit.vectors.registry import register_vector
from wallet_self_audit.verdict import VerdictWithoutKey


@register_vector
class PrngAuditPlugin(VectorPlugin):
    """PRNG audit (Milk Sad / Randstorm / Brainwallet)."""

    name = "prng_audit"
    description = (
        "Detect Milk Sad (CVE-2023-39910), Randstorm, and brainwallet-derived "
        "keys via offline candidate enumeration."
    )
    stage = Stage.ANALYSIS

    def applicability(self, ctx: AuditContext) -> bool:
        return bool(ctx.target_addresses)

    def run(self, ctx: AuditContext) -> VerdictWithoutKey:
        knobs = ctx.config.get(self.name, {})
        vectors_obj = knobs.get("vectors")
        vectors: tuple[PrngVectorName, ...]
        if vectors_obj is None:
            vectors = ("milk_sad", "randstorm", "brainwallet")
        else:
            vectors = tuple(cast(list[PrngVectorName], vectors_obj))

        n_workers_obj = knobs.get("n_workers", 0)
        n_workers = int(n_workers_obj) if isinstance(n_workers_obj, int) else 0
        mnemonic_handle = knobs.get("mnemonic_handle")
        cfg = PrngAuditConfig(
            address=ctx.address,
            target_addresses=ctx.target_addresses,
            vectors=vectors,
            n_workers=n_workers,
        )
        return run_prng_audit(cfg, mnemonic_handle=cast(MnemonicHandleT, mnemonic_handle))


@register_vector
class NonceAuditPlugin(VectorPlugin):
    """Nonce audit (r-collision + Stage-B lattice / HNP).

    The plugin requires a :class:`MempoolClient` in
    ``ctx.config["nonce_audit"]["client"]``. The CLI currently passes a
    real :class:`HttpMempoolClient`; tests pass a stub.
    """

    name = "nonce_audit"
    description = (
        "Detect ECDSA r-collisions and biased-nonce HNP recovery on outgoing "
        "transactions; verify-by-pubkey-projection (no private key materialization)."
    )
    stage = Stage.ANALYSIS

    def applicability(self, ctx: AuditContext) -> bool:
        # Nonce audit requires an address that has spent at least once;
        # the orchestrator handles the empty-history case internally.
        return bool(ctx.target_addresses)

    def run(self, ctx: AuditContext) -> VerdictWithoutKey:
        knobs = ctx.config.get(self.name, {})
        client_obj = knobs.get("client")
        if client_obj is None:
            client_obj = HttpMempoolClient()
        client = cast(MempoolClient, client_obj)
        max_txs_obj = knobs.get("max_txs", 200)
        max_txs = int(max_txs_obj) if isinstance(max_txs_obj, int) else 200
        cfg = NonceAuditConfig(address=ctx.address, max_txs=max_txs)
        return run_nonce_audit(cfg, client)


__all__ = ["NonceAuditPlugin", "PrngAuditPlugin"]
