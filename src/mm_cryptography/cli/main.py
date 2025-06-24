import importlib.metadata

import typer

from .fernet_commands import fernet_app
from .openssl_commands import openssl_app

app = typer.Typer(name="mm-crypto", help="cli tools for cryptography", no_args_is_help=True)

# Add subcommands
app.add_typer(openssl_app)
app.add_typer(fernet_app)


def version_callback(value: bool) -> None:
    """Show version information."""
    if value:
        typer.echo(f"mm-cryptography v{importlib.metadata.version('mm_cryptography')}")
        raise typer.Exit


@app.callback()
def main(
    _version: bool = typer.Option(None, "--version", callback=version_callback, is_eager=True, help="Show version"),
) -> None:
    pass


if __name__ == "__main__":
    app()
