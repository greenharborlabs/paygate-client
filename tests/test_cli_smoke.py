from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from typer.testing import CliRunner

from paygate_client import __version__
from paygate_client.cli import app


def test_cli_help_resolves() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Paygate command-line client." in result.output


def test_cli_version_resolves_without_subcommand() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == __version__


def test_pyproject_declares_tooling_commands() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text())

    assert pyproject["tool"]["poe"]["tasks"] == {
        "format": "ruff format .",
        "format-check": "ruff format --check .",
        "lint": "ruff check .",
        "test": "pytest",
        "typecheck": "mypy",
        "fix": {"shell": "ruff check . --fix && ruff format ."},
        "check": {"shell": "ruff format --check . && ruff check . && mypy && pytest"},
    }
