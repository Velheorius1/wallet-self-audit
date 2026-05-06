"""``wsa explain`` — plain-language verdict report via Claude SDK.

This is the *only* place wallet-self-audit invokes Claude. Claude is a
**report generator**, never a backend for crypto math. Hard rules:

- Input: a redacted JSON view of the verdict (``to_public_json()``) only.
  No mnemonic, no entropy, no candidate ``d`` — those never leave the
  process.
- Output: prose. The deterministic finding code (``finding`` field) is
  NOT replaced or overridden by Claude — the post-check below verifies
  Claude's draft only references the finding string verbatim.
- Reproducibility: the model id, prompt hash, and evidence hash are
  written to the audit chain (Phase 6) so a future auditor can detect
  prompt drift.

Usage::

    from wallet_self_audit.reporting.claude_explain import explain_verdict
    md = explain_verdict(verdict, model="claude-opus-4-7")

The ``claude_agent_sdk`` import is deferred until call time so the
module imports fast and tests can stub the call without installing the
SDK.

Anti-scope (HARD NO):
- Claude as orchestrator picking vectors. (Phase 5 plugin runner is
  deterministic.)
- Mnemonic / seed in any tool result.
- Claude inventing finding codes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Coroutine
from dataclasses import dataclass
from typing import Final, Protocol

from wallet_self_audit.verdict import VerdictWithoutKey

log = logging.getLogger(__name__)


_SYSTEM_PROMPT: Final[str] = """You explain Bitcoin wallet audit findings to non-experts.

Input: a JSON evidence object inside <evidence>...</evidence> tags. \
The object contains the fields: address, status, finding, confidence, \
key_fingerprint (or null), recommendation, evidence_refs (list of \
txids), audit_id, checks_performed.

Output a Markdown report with these four sections, in this exact order:

1. ## Summary — one short paragraph, no jargon.
2. ## Findings — bullet list referencing each `checks_performed` value verbatim.
3. ## What this means — explain the finding code in everyday language.
4. ## Recommended actions — actionable next steps; for VULNERABLE, lead with "Move funds NOW."

HARD RULES:
- Never invent finding codes. Use only the value of `finding` from the input.
- Never claim a private key was recovered. The input does not contain one.
- Never echo the mnemonic, entropy, or any 64-char hex other than txids.
- If `status` is SAFE, do NOT say the wallet is safe — say "no matches \
  for the configured vectors", because absence of recovery is not proof \
  of safety.
- Use British spelling consistently.
"""


# Regexes used in the post-check. We are strict: the finding string must
# appear verbatim, and no privkey-shaped 64-hex run may sneak in via
# Claude's prose.
_FINDING_RE_TEMPLATE: Final[str] = r"\b{}\b"
_PRIVKEY_LIKE_HEX: Final[re.Pattern[str]] = re.compile(r"\b[0-9a-fA-F]{64}\b")
_BIP39_LIKE: Final[re.Pattern[str]] = re.compile(r"\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b")


class ExplainPostCheckFailed(RuntimeError):
    """Raised when the LLM draft fails the deterministic post-check.

    The draft is discarded; the caller can fall back to ``render_md``.
    """


@dataclass(frozen=True, slots=True)
class ExplainProvenance:
    """Reproducibility metadata for one ``explain`` invocation.

    Persisted to the audit chain so a future auditor can detect prompt
    drift between two runs of the same audit. Contains hashes only,
    never the raw prompt or response.
    """

    model_id: str
    system_prompt_sha256: str
    evidence_sha256: str
    response_sha256: str


def _evidence_block(verdict: VerdictWithoutKey) -> str:
    """Render the redacted evidence JSON wrapped in <evidence> tags."""
    payload = verdict.to_public_json()
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return f"<evidence>{body}</evidence>"


def _post_check(draft: str, verdict: VerdictWithoutKey) -> None:
    """Validate the LLM draft. Raises :class:`ExplainPostCheckFailed`."""
    finding_re = re.compile(_FINDING_RE_TEMPLATE.format(re.escape(verdict.finding)))
    if not finding_re.search(draft):
        raise ExplainPostCheckFailed(
            f"draft does not reference finding {verdict.finding!r} verbatim"
        )
    # Allow txid-shaped 64-hex strings only if they appear in evidence_refs.
    allowed_hex64 = set(verdict.evidence_refs)
    for match in _PRIVKEY_LIKE_HEX.finditer(draft):
        h = match.group(0).lower()
        if h not in {ref.lower() for ref in allowed_hex64}:
            raise ExplainPostCheckFailed(
                "draft contains a 64-char hex string not present in evidence_refs"
            )
    if _BIP39_LIKE.search(draft):
        raise ExplainPostCheckFailed("draft contains a BIP-39-shaped mnemonic")
    # Forbid the literal substring "key recovered" / "private key recovered" —
    # we never output that, even with a fingerprint present.
    lowered = draft.lower()
    if "private key recovered" in lowered or "key was recovered" in lowered:
        raise ExplainPostCheckFailed("draft claims a private key was recovered")


def _build_user_prompt(verdict: VerdictWithoutKey) -> str:
    return f"Generate the report.\n\n{_evidence_block(verdict)}\n"


def _provenance(
    *,
    model_id: str,
    system_prompt: str,
    evidence_block: str,
    response: str,
) -> ExplainProvenance:
    def sha(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    return ExplainProvenance(
        model_id=model_id,
        system_prompt_sha256=sha(system_prompt),
        evidence_sha256=sha(evidence_block),
        response_sha256=sha(response),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
async def _call_claude(
    *,
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> str:
    """Invoke claude-agent-sdk and return the assistant text.

    Imported lazily so unit tests can monkey-patch this function before
    the SDK is installed. The SDK's options surface differs across
    versions; we pass ``system_prompt`` as a plain string (the simplest
    accepted form) and rely on the SDK's own caching configuration.
    """
    from claude_agent_sdk import ClaudeAgentOptions, query

    chunks: list[str] = []
    options = ClaudeAgentOptions(
        model=model,
        system_prompt=system_prompt,
        max_turns=1,
    )
    async for msg in query(prompt=user_prompt, options=options):
        content = getattr(msg, "content", None)
        if isinstance(content, str):
            chunks.append(content)
        elif isinstance(content, list):
            content_list: list[object] = list(content)  # pyright: ignore[reportUnknownArgumentType]
            for item in content_list:
                text = getattr(item, "text", None)
                if isinstance(text, str):
                    chunks.append(text)
    return "".join(chunks)


class CallFn(Protocol):
    """Callable contract for the (mockable) LLM invocation."""

    def __call__(
        self, *, model: str, system_prompt: str, user_prompt: str
    ) -> Coroutine[object, object, str]: ...


def explain_verdict(
    verdict: VerdictWithoutKey,
    *,
    model: str = "claude-opus-4-7",
    call_fn: CallFn | None = None,
) -> tuple[str, ExplainProvenance]:
    """Generate a plain-language report. Returns (markdown, provenance).

    ``call_fn`` is an optional injection point for tests. When ``None``
    we use :func:`_call_claude`. The function is awaited via
    ``asyncio.run`` regardless of which implementation is used.

    Raises:
        :class:`ExplainPostCheckFailed`: If the LLM draft fails the
            deterministic post-check (forbidden substrings, missing
            ``finding`` reference, etc.). Caller may fall back to
            :func:`reporting.render_md.render_md`.
    """
    import asyncio

    user_prompt = _build_user_prompt(verdict)
    evidence_block = _evidence_block(verdict)

    fn: CallFn = call_fn if call_fn is not None else _call_claude

    response: str = asyncio.run(
        fn(
            model=model,
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )
    )

    _post_check(response, verdict)
    return response, _provenance(
        model_id=model,
        system_prompt=_SYSTEM_PROMPT,
        evidence_block=evidence_block,
        response=response,
    )


__all__ = [
    "ExplainPostCheckFailed",
    "ExplainProvenance",
    "explain_verdict",
]
