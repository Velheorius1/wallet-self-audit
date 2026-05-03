"""Vector registry — ``@register_vector`` decorator + lookup.

Plugin authors decorate their :class:`VectorPlugin` subclass with
``@register_vector`` to make it discoverable. The registry is a
process-global mapping; plugins register at import time.

Tests can clear and re-populate via :func:`_reset_for_tests`. Production
code never mutates the registry directly.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TypeVar

from wallet_self_audit.vectors.base import Stage, VectorPlugin

P = TypeVar("P", bound=type[VectorPlugin])


_REGISTRY: dict[str, type[VectorPlugin]] = {}


class DuplicateVectorError(ValueError):
    """Raised when two plugins try to register under the same name."""


def register_vector(cls: P) -> P:
    """Class decorator: register ``cls`` in the process-wide vector registry.

    Validation:
    - ``cls.name`` must be non-empty.
    - No two plugins may register the same name.

    Returns the class unchanged so it can still be subclassed / used
    directly.
    """
    name = cls.name
    if not name:
        raise ValueError(f"{cls.__name__}.name must be non-empty")
    existing = _REGISTRY.get(name)
    if existing is not None and existing is not cls:
        raise DuplicateVectorError(
            f"vector {name!r} already registered: "
            f"{existing.__module__}.{existing.__name__} vs "
            f"{cls.__module__}.{cls.__name__}"
        )
    _REGISTRY[name] = cls
    return cls


def all_vectors() -> tuple[type[VectorPlugin], ...]:
    """Return every registered plugin class in registration order."""
    return tuple(_REGISTRY.values())


def vectors_for_stage(stage: Stage) -> tuple[type[VectorPlugin], ...]:
    """Return registered plugins whose ``stage`` matches."""
    return tuple(cls for cls in _REGISTRY.values() if cls.stage == stage)


def get_vector(name: str) -> type[VectorPlugin] | None:
    """Look up a plugin by name. Returns ``None`` if not registered."""
    return _REGISTRY.get(name)


def _reset_for_tests() -> None:
    """Clear the registry (test fixture only)."""
    _REGISTRY.clear()


def _bulk_register(plugins: Iterable[type[VectorPlugin]]) -> None:
    """Register an iterable of plugins (test/setup helper)."""
    for cls in plugins:
        register_vector(cls)


__all__ = [
    "DuplicateVectorError",
    "_bulk_register",
    "_reset_for_tests",
    "all_vectors",
    "get_vector",
    "register_vector",
    "vectors_for_stage",
]
