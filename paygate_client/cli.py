"""Command-line interface for paygate-client."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer

from paygate_client import __version__
from paygate_client.config import ConfigError, load_config, load_config_env
from paygate_client.diagnostics import backend_doctor, backend_pay_invoice
from paygate_client.ledger import DailySpendLedger, default_ledger_path
from paygate_client.orchestrator import (
    PaygateRequest,
    payer_from_config,
    request_with_paygate,
)
from paygate_client.policy import PolicyEngine
from paygate_client.redaction import redact_error_envelope
from paygate_client.session_cache import (
    FileCredentialCache,
    NullCredentialCache,
    default_cache_path,
    normalize_namespace,
)
from paygate_client.trace import (
    JsonTraceSink,
    MultiTraceSink,
    NullTraceSink,
    TextTraceSink,
    TraceSink,
)

DEFAULT_CONFIG_PATH = Path("~/.config/paygate-client/config.yaml")

app = typer.Typer(
    help="Paygate command-line client.",
    invoke_without_command=True,
    no_args_is_help=True,
)
backend_app = typer.Typer(
    help="Diagnose payer backend integrations.",
    no_args_is_help=True,
)
credentials_app = typer.Typer(
    help="Inspect and purge cached payment credentials.",
    no_args_is_help=True,
)
app.add_typer(backend_app, name="backend")
app.add_typer(credentials_app, name="credentials")


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
    no_pay: bool = typer.Option(
        False,
        "--no-pay",
        help="Fetch and validate a 402 challenge without paying it.",
    ),
    refresh_credential: bool = typer.Option(
        False,
        "--refresh-credential",
        help="Bypass cached credentials and force a new payment flow.",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Do not read or write cached payment credentials.",
    ),
    profile: str = typer.Option(
        "default",
        "--profile",
        help="Credential cache and budget ledger namespace for this agent.",
    ),
    cache_path: Optional[Path] = typer.Option(
        None,
        "--cache-path",
        help="Override the credential cache path.",
        file_okay=True,
        dir_okay=False,
    ),
    ledger_path: Optional[Path] = typer.Option(
        None,
        "--ledger-path",
        help="Override the daily spend ledger path.",
        file_okay=True,
        dir_okay=False,
    ),
    cache_policy: str = typer.Option(
        "challenge-defined",
        "--cache-policy",
        help=(
            "Credential reuse policy: challenge-defined, single-use, "
            "until-expiry, or max-requests."
        ),
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Emit a human-readable step trail to stderr.",
    ),
    trace_json: bool = typer.Option(
        False,
        "--trace-json",
        help="Emit structured JSON event lines to stderr.",
    ),
) -> None:
    """Send an HTTP request and satisfy a Paygate 402 challenge when required."""

    try:
        parsed_headers = _parse_headers(headers or [])
        namespace = normalize_namespace(profile)
        config_path = config.expanduser()
        loaded_config = load_config(config_path)
        policy_engine = PolicyEngine(
            loaded_config.policy,
            ledger=DailySpendLedger(
                ledger_path.expanduser()
                if ledger_path is not None
                else default_ledger_path(namespace)
            ),
        )
        credential_cache = (
            NullCredentialCache()
            if no_cache
            else FileCredentialCache(
                cache_path.expanduser()
                if cache_path is not None
                else default_cache_path(namespace),
                namespace=namespace,
            )
        )
        payer = None
        if loaded_config.payer.backend != "test-mode":
            loaded_env = load_config_env(config_path)
            payer = payer_from_config(loaded_config, env=loaded_env)
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

    paygate_request = PaygateRequest(
        method=method.upper(),
        url=url,
        headers=parsed_headers,
        body=body,
        timeout=timeout,
    )
    if payer is None:
        envelope = request_with_paygate(
            paygate_request,
            config=loaded_config,
            policy_engine=policy_engine,
            session_cache=credential_cache,
            no_pay=no_pay,
            refresh_credential=refresh_credential,
            cache_policy=cache_policy,
            session_namespace=namespace,
            trace_sink=_trace_sink(verbose=verbose, trace_json=trace_json),
        )
    else:
        envelope = request_with_paygate(
            paygate_request,
            config=loaded_config,
            payer=payer,
            policy_engine=policy_engine,
            session_cache=credential_cache,
            no_pay=no_pay,
            refresh_credential=refresh_credential,
            cache_policy=cache_policy,
            session_namespace=namespace,
            trace_sink=_trace_sink(verbose=verbose, trace_json=trace_json),
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


@credentials_app.command("list")
def credentials_list_command(
    profile: str = typer.Option(
        "default",
        "--profile",
        help="Credential cache namespace to list.",
    ),
    cache_path: Optional[Path] = typer.Option(
        None,
        "--cache-path",
        help="Override the credential cache path.",
        file_okay=True,
        dir_okay=False,
    ),
) -> None:
    """List cached payment credentials without printing secret values."""

    namespace = normalize_namespace(profile)
    cache = _credential_cache(cache_path=cache_path, namespace=namespace)
    typer.echo(
        json.dumps(
            {
                "ok": True,
                "credentials": [credential.redacted() for credential in cache.list()],
            },
            sort_keys=True,
        )
    )


@credentials_app.command("show")
def credentials_show_command(
    credential_id: str = typer.Argument(..., help="Cached credential id."),
    profile: str = typer.Option(
        "default",
        "--profile",
        help="Credential cache namespace to inspect.",
    ),
    cache_path: Optional[Path] = typer.Option(
        None,
        "--cache-path",
        help="Override the credential cache path.",
        file_okay=True,
        dir_okay=False,
    ),
) -> None:
    """Show one cached payment credential without printing secret values."""

    namespace = normalize_namespace(profile)
    cache = _credential_cache(cache_path=cache_path, namespace=namespace)
    for credential in cache.list():
        if credential.credential_id == credential_id:
            typer.echo(
                json.dumps(
                    {"ok": True, "credential": credential.redacted()},
                    sort_keys=True,
                )
            )
            return
    typer.echo(
        json.dumps(
            {
                "ok": False,
                "error": {
                    "code": "credential_not_found",
                    "message": f"credential {credential_id!r} was not found",
                },
            },
            sort_keys=True,
        )
    )
    raise typer.Exit(1)


@credentials_app.command("purge")
def credentials_purge_command(
    host: Optional[str] = typer.Option(
        None,
        "--host",
        help="Only purge credentials for this host:port.",
    ),
    service: Optional[str] = typer.Option(
        None,
        "--service",
        help="Only purge credentials for this service.",
    ),
    all_credentials: bool = typer.Option(
        False,
        "--all",
        help="Purge all cached credentials.",
    ),
    profile: str = typer.Option(
        "default",
        "--profile",
        help="Credential cache namespace to purge.",
    ),
    cache_path: Optional[Path] = typer.Option(
        None,
        "--cache-path",
        help="Override the credential cache path.",
        file_okay=True,
        dir_okay=False,
    ),
) -> None:
    """Purge cached payment credentials."""

    namespace = normalize_namespace(profile)
    cache = _credential_cache(cache_path=cache_path, namespace=namespace)
    deleted = cache.purge(host=host, service=service, all_credentials=all_credentials)
    typer.echo(json.dumps({"ok": True, "deleted": deleted}, sort_keys=True))


def _credential_cache(
    *, cache_path: Optional[Path], namespace: str
) -> FileCredentialCache:
    return FileCredentialCache(
        cache_path.expanduser()
        if cache_path is not None
        else default_cache_path(namespace),
        namespace=namespace,
    )


def _parse_headers(raw_headers: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw_header in raw_headers:
        name, separator, value = raw_header.partition(":")
        if not separator or not name.strip():
            raise ValueError(f"invalid header {raw_header!r}; expected 'Name: value'")
        headers[name.strip()] = value.strip()
    return headers


def _trace_sink(*, verbose: bool, trace_json: bool) -> TraceSink:
    sinks: list[TraceSink] = []
    if verbose:
        sinks.append(TextTraceSink())
    if trace_json:
        sinks.append(JsonTraceSink())
    if not sinks:
        return NullTraceSink()
    if len(sinks) == 1:
        return sinks[0]
    return MultiTraceSink(*sinks)
