# wallet-self-audit

Local CLI to audit **your own** Bitcoin wallet for known PRNG and nonce vulnerabilities — **before** depositing significant funds.

> **Defensive by construction.** This tool returns a verdict (`SAFE` / `SUSPICIOUS` / `VULNERABLE`) and **never outputs a private key**. If your wallet is compromised, the only recommendation is: move funds to a fresh, securely-generated wallet immediately.

## Status

- **Phase 1 (Foundation):** in progress — see [`docs/plans/2026-04-29-design.md`](docs/plans/2026-04-29-design.md)
- **Phase 2-8:** scheduled

## What it checks (v1.0)

- **PRNG audit** — your mnemonic / seed against:
  - Milk Sad (`bx seed` mt19937 + 32-bit timestamp, CVE-2023-39910)
  - Randstorm (V8 `Math.random` ≤ 2³² entropy, dominant variant)
  - Brainwallet (SHA-256 of common phrases)
- **Nonce audit** — your address's historical signatures for:
  - r-value collisions (Sony / Android Wallet 2013 case)
  - Lattice/HNP nonce bias (top-bits / low-bits / byte-bias)

## What it does NOT do

- ❌ Recover or output private keys
- ❌ Audit addresses you don't own (BIP-322 ownership gate)
- ❌ Support Taproot / Schnorr (different math, v1.1+)
- ❌ Support altcoins
- ❌ Network scanning / daemon mode
- ❌ GPU acceleration (CPU is sufficient for self-audit; v1.1+)

## Installation (after first release)

```bash
# Recommended: uv
uv tool install wallet-self-audit

# Or via pipx
pipx install wallet-self-audit

# Verify the wheel signature (Sigstore)
python -m sigstore verify identity \
    --cert-identity-regexp 'wallet-self-audit' \
    wallet_self_audit-*.whl
```

## Quick start

```bash
# First-run wizard (creates ~/.config/wsa/, ~/.local/state/wsa/)
wsa init

# Diagnose your install (ARM64 wheels, mlock, redaction, BIP-322 corpus)
wsa doctor

# Audit your mnemonic on PRNG vectors (interactive, never on disk)
wsa prng-audit

# Audit your address's signatures (requires BIP-322 ownership proof)
wsa nonce-audit bc1q... --proof signed-message.txt

# Generate a plain-language report of an audit
wsa explain <audit_id>
```

## Threat model (TL;DR)

This tool runs on **your machine**, on **your data**, with **no network calls** by default. Even so, please read [`docs/threat-model.md`](docs/threat-model.md):

1. **Best case:** boot Tails USB, run audit airgapped, destroy USB. The mnemonic never touches disk.
2. **Reasonable case:** run on your trusted Mac with screen lock and FileVault.
3. **Don't:** run on a cloud VM, in a VS Code remote container, or with a clipboard manager that logs hex.

The tool refuses to start in Jupyter / IPython (those cache `_`, `__`, `___`).

## Architecture (v1.0)

- **`VerdictWithoutKey`** — frozen dataclass, structurally incapable of carrying a 32-byte secret. Class invariant enforced in `__post_init__`.
- **`Secret`** — context-manager wrapping `bytearray` with `ctypes.memset` zero-overwrite on exit.
- **BIP-322 ownership gate** — required before any `nonce-audit`. Verified locally via `bip322` (rust-bitcoin wrapper).
- **structlog redaction** — allowlist-first, fail-closed guard catches any 64-hex / BIP-39 leak.
- **CI sentinel grep** — every test run greps the full output for known test-key fingerprints.

See [`docs/plans/2026-04-29-design.md`](docs/plans/2026-04-29-design.md) for the complete design and [`docs/threat-model.md`](docs/threat-model.md) for the full threat model.

## Development

```bash
git clone https://github.com/Velheorius1/wallet-self-audit
cd wallet-self-audit

# Install with uv (lockfile + hashes verified)
UV_NO_BUILD=1 uv sync --locked --all-extras

# Pre-commit hooks
uv run pre-commit install

# Run tests + sentinel leak gate
uv run pytest
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for full dev guide and [`SECURITY.md`](SECURITY.md) for vulnerability disclosure.

## License

[Apache-2.0](LICENSE) © 2026 Daniyar Salakhutdinov

## References

- [Milk Sad disclosure (CVE-2023-39910)](https://milksad.info/disclosure.html)
- [Randstorm research (Bitcoinjs MWC variant)](https://www.unciphered.com/blog/randstorm-you-cant-pwn-what-you-cant-see)
- [BIP-322: Generic Signed Message Format](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki)
- [Android Wallet 2013 r-collision (johoe disclosure)](https://bitcointalk.org/index.php?topic=581411.0)
