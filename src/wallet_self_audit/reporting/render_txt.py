"""Plain-text rendering of an audit verdict.

Output is human-readable, monospace-friendly, no Rich markup. Use
``cli._print_verdict_txt`` for the colourised TTY rendering; this
module is for log files / pipes / non-TTY output.
"""

from __future__ import annotations

from wallet_self_audit.verdict import VerdictWithoutKey

_BANNERS: dict[str, str] = {
    "SAFE": "[SAFE]",
    "SUSPICIOUS": "[SUSPICIOUS]",
    "VULNERABLE": "[VULNERABLE]",
}


def render_txt(verdict: VerdictWithoutKey) -> str:
    """Render ``verdict`` as a multi-line plain-text report."""
    banner = _BANNERS.get(verdict.status, f"[{verdict.status}]")
    lines: list[str] = [
        f"{banner}  finding={verdict.finding}",
        f"address: {verdict.address}",
        f"confidence: {verdict.confidence:.2f}",
        f"checks_performed: {', '.join(verdict.checks_performed) or '(none)'}",
        f"audit_id: {verdict.audit_id}",
    ]
    if verdict.key_fingerprint is not None:
        lines.append(f"key_fingerprint: {verdict.key_fingerprint}")
    if verdict.evidence_refs:
        lines.append("evidence_refs:")
        for txid in verdict.evidence_refs:
            lines.append(f"  - {txid}")
    lines.append("")
    lines.append(verdict.recommendation)
    return "\n".join(lines)


__all__ = ["render_txt"]
