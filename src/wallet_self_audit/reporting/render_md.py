"""Markdown rendering of an audit verdict — for ``docs/`` and shared reports."""

from __future__ import annotations

from wallet_self_audit.verdict import VerdictWithoutKey

_HEADERS: dict[str, str] = {
    "SAFE": "✅ SAFE",
    "SUSPICIOUS": "⚠️ SUSPICIOUS",
    "VULNERABLE": "🚨 VULNERABLE",
}


def render_md(verdict: VerdictWithoutKey) -> str:
    """Render ``verdict`` as a Markdown report."""
    header = _HEADERS.get(verdict.status, verdict.status)
    checks_md = ", ".join(f"`{c}`" for c in verdict.checks_performed) or "_(none)_"
    parts: list[str] = [
        f"# {header} — {verdict.address}",
        "",
        "## Summary",
        "",
        f"- **Finding:** `{verdict.finding}`",
        f"- **Confidence:** {verdict.confidence:.2f}",
        f"- **Checks performed:** {checks_md}",
        f"- **Audit ID:** `{verdict.audit_id}`",
    ]
    if verdict.key_fingerprint is not None:
        parts.append(f"- **Key fingerprint:** `{verdict.key_fingerprint}`")
    if verdict.evidence_refs:
        parts.append("")
        parts.append("## Evidence (transaction IDs)")
        parts.append("")
        for txid in verdict.evidence_refs:
            parts.append(f"- `{txid}`")
    parts.append("")
    parts.append("## Recommended action")
    parts.append("")
    parts.append(verdict.recommendation)
    parts.append("")
    return "\n".join(parts)


__all__ = ["render_md"]
