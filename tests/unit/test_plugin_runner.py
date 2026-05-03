"""Unit tests for the plugin registry, base contract, and runner."""

from __future__ import annotations

import pytest

from wallet_self_audit.runner import StageResult, run_plugins
from wallet_self_audit.vectors.base import AuditContext, Stage, VectorPlugin
from wallet_self_audit.vectors.registry import (
    DuplicateVectorError,
    _bulk_register,
    all_vectors,
    get_vector,
    register_vector,
    vectors_for_stage,
)
from wallet_self_audit.verdict import VerdictWithoutKey


# ---------------------------------------------------------------------------
# AuditContext basics
# ---------------------------------------------------------------------------
def test_audit_context_put_get_namespacing() -> None:
    ctx = AuditContext(address="bc1qx", target_addresses=frozenset({"bc1qx"}))
    ctx.put("a", "k", 1)
    ctx.put("b", "k", 2)
    assert ctx.get("a", "k") == 1
    assert ctx.get("b", "k") == 2
    assert ctx.get("missing", "k", default=42) == 42


def test_audit_context_get_unknown_namespace() -> None:
    ctx = AuditContext(address="bc1qx", target_addresses=frozenset({"bc1qx"}))
    assert ctx.get("nope", "k") is None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
class _FakePluginA(VectorPlugin):
    name = "fake_a"
    description = "test plugin A"
    stage = Stage.ANALYSIS

    def applicability(self, ctx: AuditContext) -> bool:
        return True

    def run(self, ctx: AuditContext) -> VerdictWithoutKey:
        return VerdictWithoutKey(
            address=ctx.address,
            status="SAFE",
            finding="none",
            confidence=0.9,
            key_fingerprint=None,
            recommendation="ok",
            evidence_refs=(),
            audit_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            checks_performed=("fake_a",),
        )


class _FakePluginCrash(VectorPlugin):
    name = "fake_crash"
    description = "test plugin that crashes"
    stage = Stage.ANALYSIS

    def applicability(self, ctx: AuditContext) -> bool:
        return True

    def run(self, ctx: AuditContext) -> VerdictWithoutKey:
        raise RuntimeError("boom")


class _FakePluginNotApplicable(VectorPlugin):
    name = "fake_skip"
    description = "test plugin that opts out"
    stage = Stage.ANALYSIS

    def applicability(self, ctx: AuditContext) -> bool:
        return False

    def run(self, ctx: AuditContext) -> VerdictWithoutKey:  # pragma: no cover
        raise AssertionError("run() must not be called when applicability is False")


@pytest.fixture
def isolated_registry() -> None:
    """Save & clear the global registry, then restore after the test."""
    from wallet_self_audit.vectors import registry as reg

    saved = dict(reg._REGISTRY)
    reg._reset_for_tests()
    yield
    reg._reset_for_tests()
    for name, cls in saved.items():
        reg._REGISTRY[name] = cls


def test_register_vector_adds_class(isolated_registry: None) -> None:
    register_vector(_FakePluginA)
    assert get_vector("fake_a") is _FakePluginA
    assert _FakePluginA in all_vectors()


def test_register_vector_rejects_empty_name(isolated_registry: None) -> None:
    class Bad(VectorPlugin):
        name = ""
        description = "no name"

        def applicability(self, ctx: AuditContext) -> bool:
            return True

        def run(self, ctx: AuditContext) -> VerdictWithoutKey:  # pragma: no cover
            raise NotImplementedError

    with pytest.raises(ValueError, match="non-empty"):
        register_vector(Bad)


def test_register_vector_rejects_duplicate(isolated_registry: None) -> None:
    register_vector(_FakePluginA)

    class Other(VectorPlugin):
        name = "fake_a"
        description = "another one"

        def applicability(self, ctx: AuditContext) -> bool:
            return True

        def run(self, ctx: AuditContext) -> VerdictWithoutKey:  # pragma: no cover
            raise NotImplementedError

    with pytest.raises(DuplicateVectorError, match="already registered"):
        register_vector(Other)


def test_register_vector_idempotent(isolated_registry: None) -> None:
    """Re-registering the SAME class is a no-op."""
    register_vector(_FakePluginA)
    register_vector(_FakePluginA)
    assert get_vector("fake_a") is _FakePluginA


def test_vectors_for_stage_filters(isolated_registry: None) -> None:
    register_vector(_FakePluginA)
    assert _FakePluginA in vectors_for_stage(Stage.ANALYSIS)
    assert _FakePluginA not in vectors_for_stage(Stage.DISCOVERY)


def test_bulk_register(isolated_registry: None) -> None:
    _bulk_register([_FakePluginA])
    assert get_vector("fake_a") is _FakePluginA


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def test_runner_returns_one_result_per_applicable_plugin(
    isolated_registry: None,
) -> None:
    register_vector(_FakePluginA)
    register_vector(_FakePluginNotApplicable)

    ctx = AuditContext(address="bc1qx", target_addresses=frozenset({"bc1qx"}))
    results = run_plugins(ctx)

    assert len(results) == 1
    assert isinstance(results[0], StageResult)
    assert results[0].plugin_name == "fake_a"
    assert results[0].verdict.status == "SAFE"


def test_runner_isolates_crashes(isolated_registry: None) -> None:
    register_vector(_FakePluginA)
    register_vector(_FakePluginCrash)

    ctx = AuditContext(address="bc1qx", target_addresses=frozenset({"bc1qx"}))
    results = run_plugins(ctx)

    assert len(results) == 2
    by_name = {r.plugin_name: r for r in results}
    assert by_name["fake_a"].verdict.status == "SAFE"
    assert by_name["fake_crash"].verdict.status == "SUSPICIOUS"
    assert by_name["fake_crash"].verdict.confidence == 0.0
    assert "crashed" in by_name["fake_crash"].verdict.recommendation


def test_runner_walks_stages_in_order(isolated_registry: None) -> None:
    """Multiple stages register; run_plugins must call them in IntEnum order."""
    log: list[str] = []

    class Discovery(VectorPlugin):
        name = "log_discovery"
        description = "test"
        stage = Stage.DISCOVERY

        def applicability(self, ctx: AuditContext) -> bool:
            return True

        def run(self, ctx: AuditContext) -> VerdictWithoutKey:
            log.append("discovery")
            return _safe(ctx, "log_discovery")

    class Analysis(VectorPlugin):
        name = "log_analysis"
        description = "test"
        stage = Stage.ANALYSIS

        def applicability(self, ctx: AuditContext) -> bool:
            return True

        def run(self, ctx: AuditContext) -> VerdictWithoutKey:
            log.append("analysis")
            return _safe(ctx, "log_analysis")

    class Synthesis(VectorPlugin):
        name = "log_synthesis"
        description = "test"
        stage = Stage.SYNTHESIS

        def applicability(self, ctx: AuditContext) -> bool:
            return True

        def run(self, ctx: AuditContext) -> VerdictWithoutKey:
            log.append("synthesis")
            return _safe(ctx, "log_synthesis")

    # Register out of order; runner must still execute discovery → analysis → synthesis.
    register_vector(Synthesis)
    register_vector(Analysis)
    register_vector(Discovery)

    ctx = AuditContext(address="bc1qx", target_addresses=frozenset({"bc1qx"}))
    run_plugins(ctx)
    assert log == ["discovery", "analysis", "synthesis"]


def _safe(ctx: AuditContext, name: str) -> VerdictWithoutKey:
    return VerdictWithoutKey(
        address=ctx.address,
        status="SAFE",
        finding="none",
        confidence=0.9,
        key_fingerprint=None,
        recommendation="ok",
        evidence_refs=(),
        audit_id="00000000-0000-0000-0000-000000000000",
        checks_performed=(name,),
    )


# ---------------------------------------------------------------------------
# Real plugin metadata sanity (covers the top-level imports of plugins.py)
# ---------------------------------------------------------------------------
def test_real_plugins_import_and_register() -> None:
    """Importing ``plugins`` registers PrngAuditPlugin and NonceAuditPlugin.

    We don't run them (one wants a live mempool client). We just check
    that they show up in the registry with the right metadata.
    """
    from wallet_self_audit.vectors import plugins as _plugins  # noqa: F401

    assert get_vector("prng_audit") is not None
    assert get_vector("nonce_audit") is not None

    nonce = get_vector("nonce_audit")
    assert nonce is not None
    name, desc, stage, _requires = nonce.metadata()
    assert name == "nonce_audit"
    assert "ECDSA" in desc or "nonce" in desc.lower()
    assert stage == Stage.ANALYSIS
