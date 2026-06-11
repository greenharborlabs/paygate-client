from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from typer.testing import CliRunner

from paygate_client.cli import app


def test_cli_help_resolves() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Paygate command-line client." in result.output


def test_pyproject_declares_tooling_commands() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text())

    assert pyproject["tool"]["poe"]["tasks"] == {
        "test": "pytest",
        "format": "ruff format .",
        "lint": "ruff check .",
        "typecheck": "mypy",
    }
