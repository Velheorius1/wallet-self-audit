"""Three-stage plugin runner with bulkhead failure isolation.

Walks ``Stage.DISCOVERY → Stage.ANALYSIS → Stage.SYNTHESIS`` and runs
each registered plugin in stage order. Within a stage, plugins are
isolated: a crashing plugin is converted into a SUSPICIOUS verdict
(finding="none", checks_performed=("<plugin_name>",)) so the rest of
the audit continues. The crash trace is logged at ERROR.

The runner does not implement a process pool in v1.0 — vectors run in
the calling process. v1.1 may add a multiprocessing backend for the
costly ANALYSIS plugins (lattice mainly).
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from wallet_self_audit.vectors.base import AuditContext, Stage, VectorPlugin
from wallet_self_audit.vectors.registry import all_vectors
from wallet_self_audit.verdict import VerdictWithoutKey

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class StageResult:
    """One plugin's verdict, with metadata."""

    plugin_name: str
    verdict: VerdictWithoutKey


def _bulkhead_run(plugin: VectorPlugin, ctx: AuditContext) -> StageResult:
    """Run one plugin under try/except. Crashes → SUSPICIOUS verdict."""
    try:
        verdict = plugin.run(ctx)
        return StageResult(plugin_name=plugin.name, verdict=verdict)
    except Exception:
        # Bulkhead: log and convert any exception into a SUSPICIOUS verdict
        # so a crashing vector doesn't take down the whole audit.
        log.exception("plugin %r crashed", plugin.name)
        fallback = VerdictWithoutKey(
            address=ctx.address,
            status="SUSPICIOUS",
            finding="none",
            confidence=0.0,
            key_fingerprint=None,
            recommendation=(
                f"Vector {plugin.name!r} crashed during the audit; treat "
                f"this result as inconclusive. Check the logs for details."
            ),
            evidence_refs=(),
            audit_id=str(uuid.uuid4()),
            checks_performed=(plugin.name,),
        )
        return StageResult(plugin_name=plugin.name, verdict=fallback)


def run_plugins(ctx: AuditContext) -> list[StageResult]:
    """Run every registered plugin (in stage order) under bulkhead."""
    results: list[StageResult] = []
    for stage in (Stage.DISCOVERY, Stage.ANALYSIS, Stage.SYNTHESIS):
        for plugin_cls in all_vectors():
            if plugin_cls.stage != stage:
                continue
            plugin = plugin_cls()
            if not plugin.applicability(ctx):
                log.debug("skipping plugin %r — applicability=False", plugin.name)
                continue
            results.append(_bulkhead_run(plugin, ctx))
    return results


__all__ = ["StageResult", "run_plugins"]
