"""CLI smoke test for ``wsa prng-audit``."""

from __future__ import annotations

import hashlib

from typer.testing import CliRunner

from wallet_self_audit.cli import app
from wallet_self_audit.prng.derive import addresses_from_privkey

runner = CliRunner()


def test_prng_audit_help_reachable() -> None:
    result = runner.invoke(app, ["prng-audit", "--help"])
    assert result.exit_code == 0
    assert "Run the PRNG audit" in result.stdout


def test_prng_audit_unknown_vector_rejected() -> None:
    result = runner.invoke(
        app,
        ["prng-audit", "bc1qfoo", "--vectors", "nonexistent_vector"],
    )
    assert result.exit_code == 2
    assert "Unknown vector" in result.stdout


def test_prng_audit_brainwallet_password_returns_vulnerable_json() -> None:
    """End-to-end: known brainwallet → JSON output → status=VULNERABLE."""
    pk = hashlib.sha256(b"password").digest()
    addrs = addresses_from_privkey(pk)
    assert addrs.p2pkh_bip44 is not None

    result = runner.invoke(
        app,
        [
            "prng-audit",
            addrs.p2pkh_bip44,
            "--vectors",
            "brainwallet",
            "--output",
            "json",
            "--workers",
            "1",
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert '"status"' in result.stdout
    assert "VULNERABLE" in result.stdout
    assert "brainwallet" in result.stdout


def test_prng_audit_invalid_output_format_rejected() -> None:
    pk = hashlib.sha256(b"password").digest()
    addrs = addresses_from_privkey(pk)
    assert addrs.p2pkh_bip44 is not None
    result = runner.invoke(
        app,
        [
            "prng-audit",
            addrs.p2pkh_bip44,
            "--vectors",
            "brainwallet",
            "--output",
            "yaml",
            "--workers",
            "1",
        ],
    )
    assert result.exit_code == 2
    assert "Unknown --output" in result.stdout
