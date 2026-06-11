"""Command-line interface for paygate-client."""

import typer

from paygate_client import __version__

app = typer.Typer(
    help="Paygate command-line client.",
    no_args_is_help=True,
)


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
