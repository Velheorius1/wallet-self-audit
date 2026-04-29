# Contributing to wallet-self-audit

Thanks for your interest. This is a **defensive security tool**; contributions are held to a higher bar than typical OSS.

## Code of Conduct

Be excellent to each other. Off-topic, harassing, or destructive behavior in issues/PRs results in immediate ban.

## Hard Rules (no exceptions)

1. **Never log a private key.** Not in stdout, stderr, logs, audit reports, error messages, or stack traces. The `redaction.fail_closed_guard` exists; do not bypass it.
2. **No `f"{secret}"` in any logger call.** Use structured kwargs only: `logger.info("event", address=addr)`. Ruff `G004` enforces this.
3. **No `bytes(Secret)` outside of `with Secret() as s:` blocks.** Use `s.view()` to get a `memoryview`.
4. **No new dependency without a CVE history check.** Run `uv run pip-audit` before adding a dep.
5. **No source builds in CI.** All deps must have ARM64 wheels for macos-14 + ubuntu-latest. `UV_NO_BUILD=1 uv sync --locked` must succeed.
6. **No silent fallback in `OwnershipProof.verify()`.** Address-type pre-classification is strict; if an address can't be cleanly classified, raise.
7. **No deviation from `VerdictWithoutKey` contract.** All audit functions return this type. Adding a field requires updating `__post_init__` invariants and `to_public_json()` allowlist.

## Dev setup

```bash
git clone https://github.com/Velheorius1/wallet-self-audit
cd wallet-self-audit

# Python 3.11+
uv python install 3.11

# Reproducible install, no source builds
UV_NO_BUILD=1 uv sync --locked --all-extras

# Pre-commit hooks (ruff, gitleaks, bandit, hex-grep, mypy)
uv run pre-commit install
```

## Daily loop

```bash
# Run tests + coverage
uv run pytest

# Lint (auto-fix)
uv run ruff check --fix .
uv run ruff format .

# Type check
uv run mypy src
uv run pyright src

# Manual leak gate (CI does this automatically)
set -o pipefail
uv run pytest 2>&1 | tee test_output.log
grep -F -f tests/fixtures/sentinel.txt test_output.log && echo "LEAK!" || echo "ok"
```

## PR checklist

- [ ] All CI checks green (matrix: macos-14 + ubuntu-latest × Python 3.11/3.12/3.13)
- [ ] `pytest -ra` passes with coverage ≥ 85%
- [ ] `mypy --strict` clean
- [ ] `pyright --strict` clean (on `src/wallet_self_audit/`)
- [ ] `bandit` clean
- [ ] `pip-audit` clean
- [ ] No new 64-char hex strings in diff (or annotated `FIXTURE_OK`)
- [ ] If adding a field to `VerdictWithoutKey`: invariant test added, `to_public_json()` allowlist updated
- [ ] If adding a logger call: structured kwargs only, `G004` clean
- [ ] If adding a dep: justification in PR, lockfile updated, `pip-audit` clean

## Architecture decisions

See [`docs/plans/2026-04-29-design.md`](docs/plans/2026-04-29-design.md) for the full design and rationale (15 expert analyses synthesized).

Major architectural changes require a new design entry in `docs/plans/YYYY-MM-DD-<topic>.md` with:
- Job Story (KOGDA → ХОЧУ → ЧТОБЫ + emotion)
- Anti-scope (what we won't do)
- Numerical scoring of priorities (P×I, /10)
- Evidence-based reasoning (cite sources)

## Testing strategy (Testing Trophy)

- **Unit (5-10 small tests/module):** invariants, edge cases, type checks
- **Integration (10-15, highest ROI):** BIP-322 corpus, DER round-trip, redaction E2E
- **Property (hypothesis):** crypto invariants (any valid input → expected output)
- **E2E (1-2):** synthetic vulnerable wallet → assert `VULNERABLE` verdict + correct fingerprint
- **Security (non-negotiable):** sentinel leak gate, bypass attempts on `VerdictWithoutKey`

## Release process

Maintainers only. See `.github/workflows/release.yml`.

```bash
# Tag a release
git tag v1.0.0
git push --tags

# CI builds + publishes via PyPI Trusted Publishing + Sigstore attestations.
```

## Questions?

Open a GitHub Discussion (preferred) or issue. For security-sensitive questions, see [`SECURITY.md`](SECURITY.md).
