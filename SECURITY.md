# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `wallet-self-audit`, please **do not** open a public issue. Instead:

1. Email the maintainer at the address listed in the [GitHub profile](https://github.com/Velheorius1) — or open a [GitHub Security Advisory](https://github.com/Velheorius1/wallet-self-audit/security/advisories/new) (preferred).
2. Provide a detailed description, reproduction steps, and (if possible) a proposed mitigation.
3. Allow up to **14 days** for an initial triage response.

We treat the following as **critical** and aim to ship fixes within **7 days** of confirmation:

- **Any path that exposes a private key** in stdout/stderr/logs/audit reports/crash dumps/error messages.
- Tampering with `VerdictWithoutKey` invariants (e.g. silent `setattr`, deepcopy propagation of `Secret`).
- Bypass of the BIP-322 ownership gate.
- Bypass of the redaction `fail_closed_guard`.
- Supply-chain compromise (lockfile drift, malicious wheel substitution).

## Threat Model

See [`docs/threat-model.md`](docs/threat-model.md) for the complete threat model and graceful-degradation honesty.

**Short version:** this tool reduces — but does not eliminate — the risk of running an audit on a possibly-compromised host. The only fully safe configuration is **airgap**: boot Tails USB, run audit with no network interface, destroy the USB after.

## Security Invariants

The following are non-negotiable invariants enforced by code + tests + CI:

| # | Invariant | Enforcement |
|---|-----------|------------|
| I1 | `VerdictWithoutKey` cannot carry a 32-byte secret | `__post_init__` invariant + `slots=True` + frozen + tuple fields |
| I2 | No private key fingerprint appears in any log/stdout/stderr | `redaction.fail_closed_guard` + CI sentinel grep |
| I3 | `nonce-audit` requires verified BIP-322 ownership proof | `ownership.OwnershipProof.verify()` strict pre-classification |
| I4 | `Secret` cannot be pickled, deepcopied, or repr'd as bytes | `__reduce__` / `__deepcopy__` raise; `__repr__` shows metadata |
| I5 | Tool refuses to start in Jupyter / IPython / `python -i` | `hardening.harden_process()` checks at import |
| I6 | All deps are reproducibly installable (no source builds in CI) | `UV_NO_BUILD=1 uv sync --locked` in CI |
| I7 | Releases are Sigstore-signed via PyPI Trusted Publishing | `release.yml` separated build/publish jobs with `id-token: write` only on publish |

## Disclosure Timeline (Coordinated)

For confirmed vulnerabilities:

1. **Day 0:** Triage acknowledgment.
2. **Day 1-7:** Patch development + verification.
3. **Day 7-14:** Coordinated public disclosure with reporter credit.
4. **Day 14+:** Public CVE filing (if applicable).

Reporters who follow coordinated disclosure are credited in the release notes.

## Out of Scope

- Vulnerabilities in upstream dependencies (report to those projects directly; we'll bump pins).
- Theoretical attacks requiring root/physical access (these are documented in the threat model as known limitations).
- Vulnerabilities in BIP-322 spec / `bip322` PyPI package itself (report to [rust-bitcoin/bip322](https://github.com/rust-bitcoin/bip322)).

## Hall of Fame

Reporters of confirmed vulnerabilities will be listed here (with consent).
