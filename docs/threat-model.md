# Threat Model — wallet-self-audit

> **Honesty first.** This document describes both what `wallet-self-audit` defends against and what it **cannot** defend against. Read both before running it on a real wallet.

## TL;DR

| Risk | Mitigated? | Notes |
|------|-----------|-------|
| Private key in stdout/stderr/logs | ✅ Yes | `VerdictWithoutKey` + `redaction.fail_closed_guard` + CI sentinel grep |
| Key extraction by silent attribute injection | ✅ Yes | `slots=True` + `frozen=True` on verdict, `__reduce__` raises on Secret |
| Pickle/deepcopy leaking Secret | ✅ Yes | `__reduce__` / `__deepcopy__` raise |
| Tool used against someone else's wallet | ✅ Yes (BIP-322 gate for nonce-audit) | `prng-audit` requires mnemonic, which is itself proof of ownership |
| Compromised host (keylogger, screen capture, RAT) | ❌ No | Use airgap (Tails USB) for actual audit |
| Cold-boot RAM attack | ⚠️ Partial | `Secret` zeroes via `ctypes.memset` + `gc.collect()`; pure Python cannot fully guarantee |
| Swap file containing key material | ⚠️ Partial | Per-buffer `mlock` works for 32-byte secrets; full process `mlockall` often EPERM on macOS |
| Core dump containing memory | ✅ Yes | `RLIMIT_CORE=(0,0)` set in `harden_process()` |
| Jupyter / IPython caching `_`, `__`, `___` | ✅ Yes | Tool refuses to start in those environments |
| `python -i` post-mortem REPL | ✅ Yes | `sys.flags.interactive` check at module import |
| Subinterpreter heap sharing (PEP 684) | ✅ Yes | Refuses to start under `_xxsubinterpreters` |
| tracemalloc / sys.settrace heap snapshots | ✅ Yes | Both disabled in `harden_process()` |
| Compromised PyPI dependency | ⚠️ Partial | `uv.lock` SHA-256 verification + Sigstore attestations + `pip-audit` weekly cron |
| Time-of-check to time-of-use on wallet binary | ❌ No | Outside scope; user must verify their wallet binary checksums separately |

## Recommended runtime configurations (best → acceptable)

### 🟢 Best: Airgap (Tails USB)

1. Boot Tails USB on a clean machine (no internet during audit).
2. Install `wallet-self-audit` via offline PyPI mirror (or pre-built USB).
3. Run `wsa prng-audit` interactively. Type mnemonic via `getpass`.
4. Transcribe verdict (paper). Destroy USB after.

This is the only configuration where compromise of the host machine does not compromise the audit.

### 🟡 Acceptable: Trusted Mac

1. M-series Mac with FileVault on, screen lock < 1 minute, no remote management.
2. Close all clipboard managers (`Maccy`, `Paste`, etc.) — they log clipboard content.
3. Quit all browser sessions to wallet sites (Sparrow, Electrum) before running.
4. Run `wsa doctor` first; if `mlock_available=False`, decide whether to proceed.
5. Run audit. Verdict is shown via Rich; do not screenshot.

### 🔴 Don't

- Cloud VM (AWS, DigitalOcean, etc.) — VM hypervisor can read RAM.
- VS Code Remote / dev containers — sends terminal output to control plane.
- Shared/work machine — root user can read process memory.
- Tmux/screen session that's logged elsewhere.
- Inside a Docker container with mounted `~/.bitcoin/` — illusion of isolation.

## What the tool defends against, layer by layer

### Layer 1: Type system (compile time, kind of)

`VerdictWithoutKey` is a `frozen=True, slots=True, kw_only=True` dataclass. The class invariant in `__post_init__` rejects:

- Any string field (other than `audit_id` / `txid` allowlist) containing > 16 hex characters.
- `confidence` outside `[0.0, 1.0]`.
- `key_fingerprint` not exactly 16 lowercase hex characters (when not `None`).
- `evidence_refs` containing anything other than 64-hex txid strings.

`slots=True` prevents `object.__setattr__(v, "privkey", "...")` from succeeding silently.

### Layer 2: `Secret` ephemeral byte container

Backed by `bytearray`, but:

- Only usable inside `with Secret(n) as s:` block.
- `s.burn()` calls `ctypes.memset(addr, 0, n)` + `gc.collect()` on `__exit__`.
- `__hash__ = None` — no hash caching as side channel.
- `__reduce__` raises — no pickling.
- `__deepcopy__` raises — no propagation.
- `__repr__` shows metadata (`<Secret n=32 burned=True>`), never bytes.

**Honest limitation:** pure Python cannot guarantee zeroization. CPython's small-allocator may keep a freed `bytearray`'s storage in a free list until next allocation overwrites it. C-extensions (coincurve) release the GIL and may copy bytes into their own buffers. **Layer 4 (mlock + airgap) is the real defense.**

### Layer 3: structlog redaction

Processor pipeline:

1. `allowlist_filter` — only fields in `ALLOWLIST_FIELDS` survive (drops everything else).
2. `suspect_hex_scrub` — regex sweep on remaining string values.
3. `fail_closed_guard` — raises `RuntimeError` if any 64-hex / 128-hex / BIP-39 phrase pattern appears.

**Honest limitation:** redaction is belt-and-braces. The deeper truth from `pyca/cryptography`: they don't log secrets at all. That's the only fully safe pattern.

### Layer 4: OS hardening (`harden_process()`)

At module import:

- `RLIMIT_CORE = (0, 0)` — no core dumps.
- Per-buffer `mlock` probe — reports availability via `wsa doctor`.
- Refuse Jupyter / IPython / `python -i` / subinterpreters.
- Disable `tracemalloc` and `sys.settrace`.

**Graceful degradation:** if `mlock` is unavailable (unprivileged on macOS commonly), the tool warns and continues. It does not fail-closed because that would prevent legitimate auditing on most user setups.

### Layer 5: BIP-322 ownership gate

Before any `nonce-audit` fetches blockchain data:

1. Tool generates challenge: `wallet-self-audit::v1::<address>::<utc-iso8601>::<32B-hex-nonce>`.
2. User signs via their own wallet (Sparrow / Electrum 4.5+ / Bitcoin Core 25+ / Trezor / Ledger fw≥2.x).
3. Tool verifies locally via `bip322` (rust-bitcoin wrapper, libsecp256k1).
4. Strict address-type pre-classification — no silent fallback to BIP-137 on segwit/taproot.
5. Replay store rejects re-use; TTL = 24h sliding window.

This makes it impossible to use `wallet-self-audit` against someone else's address — the only thing you can do without ownership is the `--informational` mode which shows public information only (`collisions_found: bool`, `outgoing_tx_count: int`).

### Layer 6: Supply chain

- `uv.lock` with SHA-256 hashes for every dependency.
- `UV_NO_BUILD=1` in CI prevents source builds.
- Sigstore attestations on every release (PyPI Trusted Publishing).
- Weekly `pip-audit` cron filing issues for new CVEs.
- Custom `gitleaks.toml` rule for Bitcoin private keys (default gitleaks misses these).

## Acknowledged limitations

1. **Pure Python cannot defeat motivated attackers with host access.** `Secret` is best-effort. The mathematical recovery code in Phase 3-4 will live in coincurve C internally and never materialize `d` in Python int form (`verify-by-pubkey-projection`).

2. **`bip322==0.2.0` is young (released 2025-11-10).** Not yet third-party audited. Mitigation: corpus regression tests (`tests/integration/test_ownership.py`) using vectors from `bitcoin/bips`, `rust-bitcoin/bip322`, and `ACken2/bip322-js`.

3. **macOS `mlockall` often fails for unprivileged processes.** We probe + degrade rather than fail-closed. Users who need strong RAM protection should boot Tails.

4. **The audit reads your blockchain history.** `nonce-audit` fetches transaction data from `mempool.space` (or your configured node). This is public data, but the request pattern reveals "this address is being audited" to the API operator. Use `--informational` for public-only checks; for paranoia, run your own mempool.space instance.

## See also

- [`SECURITY.md`](../SECURITY.md) — vulnerability disclosure and security invariants
- [`docs/airgap-setup.md`](airgap-setup.md) — full Tails USB setup walkthrough
- [`docs/plans/2026-04-29-design.md`](plans/2026-04-29-design.md) — complete architectural design
