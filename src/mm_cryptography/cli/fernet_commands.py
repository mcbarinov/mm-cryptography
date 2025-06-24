import os
from pathlib import Path
from typing import Annotated

import typer

from mm_cryptography import fernet_decrypt, fernet_encrypt, fernet_generate_key

from .utils import read_input, write_output

fernet_app = typer.Typer(name="fernet", help="Fernet symmetric encryption commands", no_args_is_help=True)


@fernet_app.command(name="generate-key")
def generate_key() -> None:
    """Generate a new Fernet encryption key."""
    key = fernet_generate_key()
    typer.echo(key)


@fernet_app.command()
def encrypt(
    key: Annotated[str | None, typer.Option("--key", "-k", help="Encryption key")] = None,
    key_file: Annotated[str | None, typer.Option("--key-file", help="File containing encryption key")] = None,
    key_env: Annotated[str | None, typer.Option("--key-env", help="Environment variable containing key")] = None,
    input_file: Annotated[str | None, typer.Option("--input", "-i", help="Input file (default: stdin)")] = None,
    output_file: Annotated[str | None, typer.Option("--output", "-o", help="Output file (default: stdout)")] = None,
) -> None:
    """Encrypt data using Fernet symmetric encryption."""
    # Get key from various sources
    encryption_key = _get_key(key, key_file, key_env)

    # Read input data
    data = read_input(input_file)

    try:
        # Encrypt
        encrypted = fernet_encrypt(data=data, key=encryption_key)
        write_output(encrypted, output_file)
    except Exception as e:
        typer.echo(f"Encryption failed: {e}", err=True)
        raise typer.Exit(1) from None


@fernet_app.command()
def decrypt(
    key: Annotated[str | None, typer.Option("--key", "-k", help="Decryption key")] = None,
    key_file: Annotated[str | None, typer.Option("--key-file", help="File containing decryption key")] = None,
    key_env: Annotated[str | None, typer.Option("--key-env", help="Environment variable containing key")] = None,
    input_file: Annotated[str | None, typer.Option("--input", "-i", help="Input file (default: stdin)")] = None,
    output_file: Annotated[str | None, typer.Option("--output", "-o", help="Output file (default: stdout)")] = None,
) -> None:
    """Decrypt data using Fernet symmetric encryption."""
    # Get key from various sources
    decryption_key = _get_key(key, key_file, key_env)

    # Read encrypted data
    encrypted_data = read_input(input_file)

    try:
        # Decrypt
        decrypted = fernet_decrypt(encoded_data=encrypted_data, key=decryption_key)
        write_output(decrypted, output_file)
    except Exception as e:
        typer.echo(f"Decryption failed: {e}", err=True)
        raise typer.Exit(1) from None


def _get_key(key: str | None, key_file: str | None, key_env: str | None) -> str:
    """Get encryption key from various sources."""
    sources_provided = sum(x is not None for x in [key, key_file, key_env])

    if sources_provided == 0:
        raise typer.BadParameter("Must provide key via --key, --key-file, or --key-env")

    if sources_provided > 1:
        raise typer.BadParameter("Can only specify one key source: --key, --key-file, or --key-env")

    if key is not None:
        return key

    if key_file is not None:
        try:
            return Path(key_file).read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            raise typer.BadParameter(f"Key file not found: {key_file}") from None
        except Exception as e:
            raise typer.BadParameter(f"Error reading key file: {e}") from e

    if key_env is not None:
        env_key = os.environ.get(key_env)
        if env_key is None:
            raise typer.BadParameter(f"Environment variable not found: {key_env}")
        return env_key

    # This should never happen
    raise typer.BadParameter("No key source provided")
