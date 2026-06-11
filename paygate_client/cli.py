"""Command-line interface for paygate-client."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer

from paygate_client import __version__
from paygate_client.config import ConfigError, load_config
from paygate_client.diagnostics import backend_doctor, backend_pay_invoice
from paygate_client.orchestrator import PaygateRequest, request_with_paygate
from paygate_client.redaction import redact_error_envelope

DEFAULT_CONFIG_PATH = Path("~/.config/paygate-client/config.yaml")

app = typer.Typer(
    help="Paygate command-line client.",
    no_args_is_help=True,
)
backend_app = typer.Typer(
    help="Diagnose payer backend integrations.",
    no_args_is_help=True,
)
app.add_typer(backend_app, name="backend")


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        help="Show the installed paygate-client version.",
    ),
) -> None:
    """Run the Paygate command-line client."""
    if version:
        typer.echo(__version__)
        raise typer.Exit()


@app.command()
def request(
    method: str = typer.Argument(..., help="HTTP method to send."),
    url: str = typer.Argument(..., help="Target URL to request."),
    config: Path = typer.Option(
        DEFAULT_CONFIG_PATH,
        "--config",
        "-c",
        help="Path to the Paygate YAML config.",
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    headers: Optional[List[str]] = typer.Option(
        None,
        "--header",
        "-H",
        help="HTTP header as 'Name: value'. May be repeated.",
    ),
    body: Optional[str] = typer.Option(
        None,
        "--body",
        "--data",
        help="Request body to send.",
    ),
    timeout: Optional[float] = typer.Option(
        None,
        "--timeout",
        help="Target request timeout in seconds.",
    ),
) -> None:
    """Send an HTTP request and satisfy a Paygate 402 challenge when required."""

    try:
        parsed_headers = _parse_headers(headers or [])
        loaded_config = load_config(config.expanduser())
    except (ConfigError, ValueError) as exc:
        typer.echo(
            json.dumps(
                redact_error_envelope(
                    {
                        "ok": False,
                        "paid": False,
                        "error": {
                            "code": "invalid_request",
                            "message": str(exc),
                        },
                    }
                ),
                sort_keys=True,
            )
        )
        raise typer.Exit(1) from exc

    envelope = request_with_paygate(
        PaygateRequest(
            method=method.upper(),
            url=url,
            headers=parsed_headers,
            body=body,
            timeout=timeout,
        ),
        config=loaded_config,
    )
    typer.echo(json.dumps(envelope, sort_keys=True))
    if not bool(envelope.get("ok")):
        raise typer.Exit(1)


@backend_app.command("doctor")
def backend_doctor_command(
    config: Path = typer.Option(
        ...,
        "--config",
        "-c",
        help="Path to the Paygate YAML config.",
        file_okay=True,
        dir_okay=False,
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit a JSON diagnostic envelope.",
    ),
) -> None:
    """Validate payer backend configuration and capabilities."""

    del json_output
    envelope = backend_doctor(config)
    typer.echo(json.dumps(envelope, sort_keys=True))
    if not bool(envelope.get("ok")):
        raise typer.Exit(1)


@backend_app.command("pay-invoice")
def backend_pay_invoice_command(
    bolt11: str = typer.Argument(..., help="BOLT11 invoice to pay."),
    config: Path = typer.Option(
        ...,
        "--config",
        "-c",
        help="Path to the Paygate YAML config.",
        file_okay=True,
        dir_okay=False,
    ),
    max_fee_sats: int = typer.Option(
        ...,
        "--max-fee-sats",
        min=0,
        help="Maximum routing fee the backend may pay.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit a JSON diagnostic envelope.",
    ),
) -> None:
    """Pay a standalone BOLT11 invoice through the configured backend."""

    del json_output
    envelope = backend_pay_invoice(
        bolt11,
        config_path=config,
        max_fee_sats=max_fee_sats,
    )
    typer.echo(json.dumps(envelope, sort_keys=True))
    if not bool(envelope.get("ok")):
        raise typer.Exit(1)


def _parse_headers(raw_headers: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw_header in raw_headers:
        name, separator, value = raw_header.partition(":")
        if not separator or not name.strip():
            raise ValueError(f"invalid header {raw_header!r}; expected 'Name: value'")
        headers[name.strip()] = value.strip()
    return headers
