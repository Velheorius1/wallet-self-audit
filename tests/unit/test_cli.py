"""Unit tests for the ``wsa`` CLI skeleton.

Uses Typer's CliRunner to invoke commands without a subprocess.
"""

from __future__ import annotations

from typer.testing import CliRunner

from wallet_self_audit.cli import app

runner = CliRunner()


def test_help_exits_zero() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "wallet-self-audit" in result.output


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "wallet-self-audit" in result.output


def test_init_creates_directories(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    # Directories should be created.
    assert (tmp_path / ".local" / "state" / "wsa").exists()
    assert (tmp_path / ".local" / "share" / "wsa").exists()
    assert (tmp_path / ".config" / "wsa").exists()
    assert (tmp_path / ".config" / "wsa" / "config.toml").exists()


def test_init_idempotent(tmp_path, monkeypatch) -> None:
    """Running init twice should not crash."""
    monkeypatch.setenv("HOME", str(tmp_path))
    runner.invoke(app, ["init"])
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0


def test_doctor_runs(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    result = runner.invoke(app, ["doctor"])
    # doctor may report some checks as failing (e.g. mlock unavailable in CI),
    # but it must not crash.
    assert result.exit_code == 0
