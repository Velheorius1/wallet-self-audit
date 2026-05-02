"""``wsa`` command-line entry point.

Phase 1 commands:
- ``wsa init``    — first-run wizard, creates state directories.
- ``wsa doctor``  — diagnose the install (wheels, mlock, redaction, fixtures).

Phase 2-4 commands (stubs in v1.0):
- ``wsa prng-audit``    — Milk Sad / Randstorm / Brainwallet check.
- ``wsa nonce-audit``   — r-collision / lattice/HNP check.
- ``wsa explain``       — Claude SDK plain-language report.
- ``wsa report``        — view past audits.

Importing this module triggers ``hardening.harden_process()`` (via the
package ``__init__``).
"""

from __future__ import annotations

import json
import platform
import sys
from importlib import import_module
from pathlib import Path
from typing import NoReturn

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import wallet_self_audit
from wallet_self_audit.logging import configure_logging

app = typer.Typer(
    name="wsa",
    help=(
        "wallet-self-audit — local Bitcoin wallet self-audit. "
        "Returns SAFE / SUSPICIOUS / VULNERABLE without ever outputting a "
        "private key."
    ),
    no_args_is_help=True,
    add_completion=False,
)

console = Console()


# ---------------------------------------------------------------------------
# Filesystem layout — XDG-compliant on Linux, mirrored on macOS.
# ---------------------------------------------------------------------------
def _state_dir() -> Path:
    """Persistent ephemeral state (replay store, audit chain)."""
    return Path.home() / ".local" / "state" / "wsa"


def _data_dir() -> Path:
    """Long-term audit data (SQLite caches per audit)."""
    return Path.home() / ".local" / "share" / "wsa"


def _config_dir() -> Path:
    """User configuration (config.toml, theme overrides)."""
    return Path.home() / ".config" / "wsa"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
@app.command()
def init() -> None:
    """First-run wizard. Creates state/data/config directories."""
    configure_logging()

    console.print(
        Panel.fit(
            "[bold]wallet-self-audit init[/bold]\n\n"
            "This will create:\n"
            f"  • {_state_dir()}\n"
            f"  • {_data_dir()}\n"
            f"  • {_config_dir()}\n\n"
            "[yellow]Important:[/yellow] for high-value audits, run from a "
            "Tails USB on an airgapped machine.\n"
            "See [cyan]docs/airgap-setup.md[/cyan] for the full walkthrough.",
            title="Welcome",
            border_style="cyan",
        )
    )

    for d in (_state_dir(), _data_dir(), _config_dir()):
        d.mkdir(parents=True, exist_ok=True)
        console.print(f"  [green]✓[/green] {d}")

    config_file = _config_dir() / "config.toml"
    if not config_file.exists():
        config_file.write_text(_default_config_toml(), encoding="utf-8")
        console.print(f"  [green]✓[/green] {config_file} (default config)")

    console.print(
        "\n[bold green]Done.[/bold green] Run [cyan]wsa doctor[/cyan] to verify your install."
    )


@app.command()
def doctor() -> None:
    """Diagnose the install. Reports wheels, mlock, redaction, BIP-322 corpus."""
    configure_logging()
    console.print("[bold]wsa doctor[/bold]\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Check", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Detail")

    # 1. Hardening status (set at package import).
    harden = wallet_self_audit._HARDEN_STATUS  # pyright: ignore[reportPrivateUsage]
    table.add_row(
        "Core dumps disabled",
        _ok(harden.get("core_dumps_disabled", False)),
        "RLIMIT_CORE=(0,0)" if harden.get("core_dumps_disabled") else "warn",
    )
    table.add_row(
        "mlock available",
        _ok(harden.get("mlock_available", False)),
        "per-buffer mlock probe ok"
        if harden.get("mlock_available")
        else "graceful degrade — airgap recommended",
    )

    # 2. Python + platform.
    table.add_row("Python", _ok(True), f"{sys.version.split()[0]} on {platform.platform()}")

    # 3. Critical wheels (importable, presumably ARM64-native).
    # btclib is added in Phase 3 (sighash); see pyproject.toml note.
    for mod_name, label in [
        ("coincurve", "coincurve (ARM64 wheel)"),
        ("bip322", "bip322 (rust-bitcoin wrapper)"),
        ("structlog", "structlog"),
        ("typer", "typer"),
        ("rich", "rich"),
    ]:
        try:
            mod = import_module(mod_name)
            ver = getattr(mod, "__version__", "ok")
            table.add_row(label, _ok(True), str(ver))
        except ImportError as exc:
            table.add_row(label, _ok(False), str(exc))

    # 4. Redaction smoke test.
    try:
        from wallet_self_audit.logging.redaction import (
            RedactionFailClosed,
            allowlist_filter,
            fail_closed_guard,
            suspect_hex_scrub,
        )

        # Test 1: allowlist drops unknown fields.
        e1 = allowlist_filter(None, "info", {"event": "x", "privkey": "deadbeef" * 8})
        assert "privkey" not in e1, "allowlist_filter didn't drop privkey"

        # Test 2: fail_closed_guard raises on long hex.
        try:
            fail_closed_guard(None, "info", {"x": "deadbeef" * 16})
            ok_guard = False
        except RedactionFailClosed:
            ok_guard = True

        table.add_row("Redaction allowlist", _ok(True), "drops unknown fields")
        table.add_row(
            "Redaction fail-closed",
            _ok(ok_guard),
            "raises on suspect 128-hex" if ok_guard else "DID NOT RAISE",
        )

        # Test 3: suspect_hex_scrub redacts.
        e3 = suspect_hex_scrub(None, "info", {"text": "x" + "a" * 64 + "y"})
        scrubbed = e3.get("text", "")
        ok_scrub = isinstance(scrubbed, str) and "[REDACTED:HEX64]" in scrubbed
        table.add_row(
            "Redaction hex scrub",
            _ok(ok_scrub),
            "[REDACTED:HEX64]" if ok_scrub else "did not scrub",
        )
    except Exception as exc:
        table.add_row("Redaction", _ok(False), f"error: {exc}")

    # 5. Verdict invariant smoke.
    try:
        from wallet_self_audit.verdict import VerdictWithoutKey

        v = VerdictWithoutKey(
            address="bc1qexample",
            status="SAFE",
            finding="none",
            confidence=0.99,
            key_fingerprint=None,
            recommendation="No issues detected.",
            evidence_refs=(),
            audit_id="00000000-0000-0000-0000-000000000000",
            checks_performed=("milk_sad", "randstorm"),
        )
        table.add_row(
            "Verdict invariant",
            _ok(True),
            f"{type(v).__name__} constructed cleanly",
        )
    except Exception as exc:
        table.add_row("Verdict invariant", _ok(False), f"error: {exc}")

    # 6. BIP-322 corpus presence.
    corpus_path = _find_test_corpus()
    if corpus_path is not None:
        try:
            data = json.loads(corpus_path.read_text(encoding="utf-8"))
            n = len(data.get("vectors", []))
            table.add_row(
                "BIP-322 corpus",
                _ok(n >= 5),
                f"{corpus_path.name}: {n} vectors" if n >= 5 else f"only {n} vectors (need ≥5)",
            )
        except Exception as exc:
            table.add_row("BIP-322 corpus", _ok(False), f"error: {exc}")
    else:
        table.add_row("BIP-322 corpus", _ok(False), "tests/fixtures/bip322/corpus.json missing")

    # 7. Sentinel file presence (CI gate).
    sentinel_path = _find_sentinel()
    if sentinel_path is not None:
        table.add_row(
            "Sentinel file",
            _ok(True),
            f"{sentinel_path}",
        )
    else:
        table.add_row("Sentinel file", _ok(False), "tests/fixtures/sentinel.txt missing")

    console.print(table)
    console.print(
        "\n[dim]Per-Secret mlock and structlog redaction are belt-and-braces. "
        "For high-value audits, see [cyan]docs/airgap-setup.md[/cyan].[/dim]"
    )


@app.command(name="prng-audit")
def prng_audit_cmd(
    addresses: list[str] = typer.Argument(  # noqa: B008
        ...,
        metavar="ADDRESS [ADDRESS ...]",
        help="One or more known receive addresses for the wallet.",
    ),
    use_mnemonic: bool = typer.Option(
        False,
        "--mnemonic",
        help=(
            "Prompt for the BIP-39 mnemonic interactively (echo disabled). "
            "Without this flag the audit runs in slower address-only mode."
        ),
    ),
    vectors: str = typer.Option(
        "milk_sad,randstorm,brainwallet",
        "--vectors",
        help="Comma-separated subset of vectors to run.",
    ),
    output: str = typer.Option(
        "txt",
        "--output",
        help="Output format: txt | json | both.",
    ),
    milk_sad_start: int = typer.Option(
        0,
        "--milk-sad-start",
        help="Milk Sad scan window start (Unix timestamp). 0 = default.",
    ),
    milk_sad_end: int = typer.Option(
        0,
        "--milk-sad-end",
        help="Milk Sad scan window end (Unix timestamp). 0 = default.",
    ),
    randstorm_s0_max: int = typer.Option(
        0,
        "--randstorm-s0-max",
        help="Randstorm scan upper bound on s0 (default 2**28).",
    ),
    workers: int = typer.Option(
        0,
        "--workers",
        help="Number of multiprocessing workers (0 = auto, P-cores).",
    ),
) -> None:
    """Run the PRNG audit (Milk Sad / Randstorm / Brainwallet).

    Examples:

      wsa prng-audit bc1qabc... --mnemonic --vectors milk_sad,brainwallet

      wsa prng-audit bc1qabc... 1Foo... --output json
    """
    from wallet_self_audit.prng import milk_sad as _milk_sad
    from wallet_self_audit.prng import randstorm as _randstorm
    from wallet_self_audit.prng.owner_input import (
        MnemonicHandle,
        prompt_mnemonic,
    )
    from wallet_self_audit.vectors.prng_audit import (
        PrngAuditConfig,
        VectorName,
        normalize_addresses,
        run_prng_audit,
    )

    configure_logging()

    # Parse vectors.
    raw_vectors = [v.strip() for v in vectors.split(",") if v.strip()]
    valid: tuple[VectorName, ...] = ("milk_sad", "randstorm", "brainwallet")
    chosen: list[VectorName] = []
    for v in raw_vectors:
        if v not in valid:
            console.print(f"[red]Unknown vector:[/red] {v!r} (valid: {', '.join(valid)})")
            raise typer.Exit(code=2)
        # ``v`` is narrowed to ``VectorName`` by the ``not in valid`` guard above.
        chosen.append(v)
    if not chosen:
        console.print("[red]No vectors selected.[/red]")
        raise typer.Exit(code=2)

    # Build address set.
    target_addresses = normalize_addresses(addresses)
    primary = next(iter(target_addresses))  # any one — used as verdict.address

    # Build window / range overrides.
    ms_start = milk_sad_start or _milk_sad.MILK_SAD_WINDOW_DEFAULT_START
    ms_end = milk_sad_end or _milk_sad.MILK_SAD_WINDOW_DEFAULT_END
    rs_s0_max = randstorm_s0_max or _randstorm.RANDSTORM_DEFAULT_S0_RANGE[1]

    # Optional mnemonic.
    handle: MnemonicHandle | None = None
    if use_mnemonic:
        # Tier-3 confirmation: user must type the last 4 chars of the
        # primary address before we open the mnemonic prompt.
        confirm = primary[-4:]
        try:
            handle = prompt_mnemonic(confirm_phrase=confirm)
        except RuntimeError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=2) from exc

    config = PrngAuditConfig(
        address=primary,
        target_addresses=target_addresses,
        vectors=tuple(chosen),
        milk_sad_window=(ms_start, ms_end),
        randstorm_s0_range=(0, rs_s0_max),
        n_workers=workers,
    )

    verdict = run_prng_audit(config, mnemonic_handle=handle)

    if output in ("txt", "both"):
        _print_verdict_txt(verdict)
    if output in ("json", "both"):
        console.print_json(json.dumps(verdict.to_public_json()))
    if output not in ("txt", "json", "both"):
        console.print(f"[red]Unknown --output:[/red] {output!r}")
        raise typer.Exit(code=2)


def _print_verdict_txt(verdict: object) -> None:
    """Render a verdict as a human-readable Rich panel."""
    from wallet_self_audit.verdict import VerdictWithoutKey

    if not isinstance(verdict, VerdictWithoutKey):
        console.print("[red]_print_verdict_txt: unexpected type[/red]")
        return

    color = {
        "SAFE": "green",
        "SUSPICIOUS": "yellow",
        "VULNERABLE": "red",
    }[verdict.status]

    body = (
        f"[bold {color}]{verdict.status}[/bold {color}]  finding=[cyan]{verdict.finding}[/cyan]\n"
        f"address: [bold]{verdict.address}[/bold]\n"
        f"confidence: {verdict.confidence:.2f}\n"
        f"checks_performed: {', '.join(verdict.checks_performed)}\n"
        f"audit_id: {verdict.audit_id}\n"
        + (f"key_fingerprint: {verdict.key_fingerprint}\n" if verdict.key_fingerprint else "")
        + f"\n{verdict.recommendation}"
    )
    console.print(
        Panel(
            body,
            title="wsa prng-audit",
            border_style=color,
        )
    )


@app.command(name="version")
def version_cmd() -> None:
    """Show version and exit."""
    console.print(f"wallet-self-audit {wallet_self_audit.__version__}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ok(value: bool) -> str:
    return "[green]✓[/green]" if value else "[red]✗[/red]"


def _default_config_toml() -> str:
    return (
        "# wallet-self-audit configuration\n"
        "# This file is created by `wsa init`. Edit with `wsa config edit`.\n\n"
        "[audit]\n"
        "# Default vectors for `prng-audit` (comma-separated).\n"
        'default_prng_vectors = ["milk_sad", "randstorm", "brainwallet"]\n\n'
        "[network]\n"
        "# Refuse to run with network interfaces up.\n"
        "require_offline = true\n\n"
        "[ui]\n"
        '# Output format: "txt" | "json" | "both"\n'
        'default_output = "txt"\n'
    )


def _find_test_corpus() -> Path | None:
    """Look for tests/fixtures/bip322/corpus.json relative to package."""
    here = Path(__file__).resolve().parent
    for cand in [
        here.parent.parent / "tests" / "fixtures" / "bip322" / "corpus.json",
        Path.cwd() / "tests" / "fixtures" / "bip322" / "corpus.json",
    ]:
        if cand.exists():
            return cand
    return None


def _find_sentinel() -> Path | None:
    """Look for tests/fixtures/sentinel.txt."""
    here = Path(__file__).resolve().parent
    for cand in [
        here.parent.parent / "tests" / "fixtures" / "sentinel.txt",
        Path.cwd() / "tests" / "fixtures" / "sentinel.txt",
    ]:
        if cand.exists():
            return cand
    return None


def main() -> NoReturn:
    """Entry point for the ``wsa`` script."""
    app()
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
