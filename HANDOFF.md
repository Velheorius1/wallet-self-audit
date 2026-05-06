# Handoff — wallet-self-audit v1.0

> Read this first when picking the project up in a new session.

## State as of 2026-05-06

**All 8 phases shipped, CI green on every branch.** Each phase lives on
its own branch under `wallet-self-audit/phase-N-*`. `main` is still at
Phase 1 (the foundation); Phase 2-8 are stacked on top of each other
and ready to be merged.

| Phase | Branch                                     | Tests | What                                                            |
| ----- | ------------------------------------------ | ----- | --------------------------------------------------------------- |
| 1     | `main`                                     | 117   | Foundation: VerdictWithoutKey, hardening, ownership, DER, CLI   |
| 2     | `wallet-self-audit/phase-2-prng-audit`     | 173   | Milk Sad / Randstorm / Brainwallet (mt19937 byte-identical)     |
| 3     | `wallet-self-audit/phase-3-nonce-audit`    | 223   | sighash + verify-by-pubkey-projection + extractor + r-collision |
| 4     | `wallet-self-audit/phase-4-lattice`        | 259   | Pure-Python LLL + Boneh-Venkatesan HNP basis                    |
| 5     | `wallet-self-audit/phase-5-plugins`        | 271   | Plugin contract + 3-stage runner + bulkhead                     |
| 6     | `wallet-self-audit/phase-6-storage`        | 299   | SQLite per-audit + 3 renderers + tamper-evident audit chain     |
| 7     | `wallet-self-audit/phase-7-claude`         | 308   | `wsa explain` via Claude SDK + deterministic post-check         |
| 8     | `wallet-self-audit/phase-8-hardening`      | 318   | BIP-322 walkthrough + cross-renderer leak gate                  |

All CI gates pass on every branch: `mypy strict`, `pyright strict`,
`ruff` check + format, `gitleaks`, `bandit`, `pip-audit`. Matrix:
3 Python (3.11/3.12/3.13) × 2 OS (macos-14, ubuntu-latest).

## To finish v1.0 (next session)

1. **Merge train.** Open PRs in order: `phase-2 → main`, then rebase
   each later branch onto the new main and PR it.

   ```sh
   gh pr create --base main --head wallet-self-audit/phase-2-prng-audit
   # … merge it via the GitHub UI (squash recommended) …
   git checkout wallet-self-audit/phase-3-nonce-audit
   git rebase main
   gh pr create --base main --head wallet-self-audit/phase-3-nonce-audit
   # … repeat for 4, 5, 6, 7, 8 …
   ```

2. **Tag v1.0.0.**

   ```sh
   git checkout main && git pull
   git tag -a v1.0.0 -m "wallet-self-audit v1.0.0"
   git push --tags
   ```

3. **Sigstore Trusted Publishing.** `release.yml` is in place; register
   the project on PyPI's Trusted Publishing UI before the first tag
   push so the workflow can claim the signing identity.

4. **Real-wallet smoke test.** The single user-facing verification we
   never did: run `wsa nonce-audit <your_address> --proof proof.json`
   on Daniyar's actual segwit address. Steps:
   1. `uv run wsa nonce-audit bc1q... --print-challenge` → copy the string
   2. Sign it in Sparrow / Bitcoin Core 25+ / Electrum / hardware wallet
   3. Save `{"challenge":"…","signature":"…"}` as `proof.json`
   4. `uv run wsa nonce-audit bc1q... --proof proof.json`

## Known tails (not blockers)

- **Coverage gate is at 50% on CI** but ~76-80% locally. xdist + Pool
  child processes drop coverage on Linux runners. Fix path documented
  in `pyproject.toml` near `--cov-fail-under`.
- **`@pytest.mark.lattice` excluded from CI** (5+ min pure-Python LLL).
  Run locally with `uv run pytest -m lattice`. A nightly cron workflow
  could pick them up — not done.
- **`fpylll` adapter** has stub-only — pure Python LLL handles dim ≤ 60
  fine, which is the realistic self-audit envelope.
- **Real Milk Sad ground-truth fixture** — only synthetic vectors so
  far. Add disclosed addresses from CVE-2023-39910 advisory before
  release if you want a published-evidence regression.

## How to run anything locally

```sh
cd ~/Desktop/wallet-self-audit/
uv sync --frozen

# Tests + lint + types (matches CI)
WSA_SKIP_HARDEN=1 uv run pytest -q -m "not lattice"
uv run ruff check . && uv run ruff format --check .
uv run mypy src
uv run pyright src

# CLI
uv run wsa --help
uv run wsa init && uv run wsa doctor
uv run wsa prng-audit bc1q... --vectors brainwallet --workers 1
uv run wsa nonce-audit bc1q... --informational
uv run wsa explain verdict.json
```

## Don't break these invariants

1. **VerdictWithoutKey** never carries a private key. `__post_init__`
   rejects any hex-run > 16 chars in `recommendation` / `finding`.
2. **Recovery never materialises `d` outside `_candidate_to_pubkey`.**
   The lattice path is the only place a candidate int briefly exists,
   and it goes out of scope on return.
3. **`wsa explain` post-check is the LLM safety net.** Drafts that
   invent finding codes / leak hex / claim "key recovered" are
   discarded; the local `render_md` fallback runs instead.
4. **Audit chain is hash-chained.** Any retroactive edit invalidates
   every later line; `verify_chain()` finds the first divergence.

GitHub: https://github.com/Velheorius1/wallet-self-audit (private)
