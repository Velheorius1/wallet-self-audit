"""Plugin contract for audit vectors.

Each audit vector (prng, nonce, future ones) is a plugin that exposes:

- A ``name`` and ``description`` for CLI listing.
- A ``stage`` (DISCOVERY → ANALYSIS → SYNTHESIS).
- An ``applicability(ctx)`` predicate so vectors can opt out of running
  when their inputs aren't satisfied (no signatures → nonce audit
  doesn't apply, etc.).
- A ``run(ctx)`` method that returns a ``VerdictWithoutKey``.

The runner walks plugins in stage order. Within a stage, plugins are
independent and isolated — a crashing plugin returns a SUSPICIOUS verdict
rather than tearing down the whole audit (the *bulkhead* pattern).

Phase 5 ships the contract + a minimal runner. The existing PRNG and
nonce audit code stays callable as-is; the plugin wrappers are thin
adapters. The CLI continues to call the orchestrator functions directly
in v1.0; the plugin runner is what we will exercise in Phase 7 and
beyond when adding a unified ``wsa audit`` command.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum

from wallet_self_audit.verdict import VerdictWithoutKey


class Stage(IntEnum):
    """Plugin stage, in execution order."""

    DISCOVERY = 1  # fetch + parse raw chain data; runs once before all others
    ANALYSIS = 2  # independent vectors that consume the discovery output
    SYNTHESIS = 3  # consume earlier vector outputs (e.g. unified report)


@dataclass(slots=True)
class AuditContext:
    """Shared per-audit context.

    Plugins read from / write to this object instead of passing data
    around explicitly. The ``cache`` is namespaced by plugin name so two
    plugins can't accidentally clobber each other's outputs.

    The ``config`` dict is keyed by plugin name and holds parsed per-vector
    config dicts. Phase 7 will tighten this with per-plugin
    ``config_schema`` (pydantic). For now we use ``object`` and require
    plugins to validate / cast their own knobs at run time.
    """

    address: str
    target_addresses: frozenset[str]
    config: dict[str, dict[str, object]] = field(default_factory=lambda: {})
    cache: dict[str, dict[str, object]] = field(default_factory=lambda: {})

    def put(self, plugin_name: str, key: str, value: object) -> None:
        """Store a value under ``plugin_name.key`` in the shared cache."""
        ns = self.cache.setdefault(plugin_name, {})
        ns[key] = value

    def get(self, plugin_name: str, key: str, default: object = None) -> object:
        """Fetch a value previously stored by ``put``."""
        ns = self.cache.get(plugin_name)
        if ns is None:
            return default
        return ns.get(key, default)


class VectorPlugin(ABC):
    """Abstract base class for audit vectors.

    Subclasses declare ``name``, ``description``, ``stage`` (and optional
    ``requires`` for SYNTHESIS plugins) as class variables, and override
    ``applicability`` + ``run``.
    """

    # Class-level metadata. Override in subclasses.
    name: str = ""
    description: str = ""
    stage: Stage = Stage.ANALYSIS
    requires: tuple[str, ...] = ()

    @abstractmethod
    def applicability(self, ctx: AuditContext) -> bool:
        """Return True iff this vector can/should run for ``ctx``."""

    @abstractmethod
    def run(self, ctx: AuditContext) -> VerdictWithoutKey:
        """Execute the vector and return a verdict."""

    # ---- helpers ---------------------------------------------------------
    @classmethod
    def metadata(cls) -> tuple[str, str, Stage, tuple[str, ...]]:
        """Return (name, description, stage, requires) — used for ``wsa vectors list``."""
        return cls.name, cls.description, cls.stage, cls.requires


__all__ = ["AuditContext", "Stage", "VectorPlugin"]
