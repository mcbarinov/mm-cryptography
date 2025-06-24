import getpass
from typing import Annotated

import typer

from mm_cryptography import OpensslAes256Cbc

from .utils import read_input, read_input_bytes, write_output, write_output_bytes

openssl_app = typer.Typer(name="openssl", help="OpenSSL AES-256-CBC encryption commands", no_args_is_help=True)


@openssl_app.command()
def encrypt(
    password: Annotated[str | None, typer.Option("--password", "-p", help="Encryption password")] = None,
    input_file: Annotated[str | None, typer.Option("--input", "-i", help="Input file (default: stdin)")] = None,
    output_file: Annotated[str | None, typer.Option("--output", "-o", help="Output file (default: stdout)")] = None,
    bytes_mode: Annotated[bool, typer.Option("--bytes", help="Use raw bytes mode")] = False,
) -> None:
    """Encrypt data using OpenSSL AES-256-CBC."""
    if password is None:
        password = typer.prompt("Enter password", hide_input=True, confirmation_prompt=True)

    cipher = OpensslAes256Cbc(password)

    if bytes_mode:
        # Raw bytes mode
        data_bytes = read_input_bytes(input_file)
        encrypted_bytes = cipher.encrypt_bytes(data_bytes)
        write_output_bytes(encrypted_bytes, output_file)
    else:
        # Base64 mode (default) - always work with strings
        data_str = read_input(input_file)
        encrypted_str = cipher.encrypt_base64(data_str)
        write_output(encrypted_str, output_file)


@openssl_app.command()
def decrypt(
    password: Annotated[str | None, typer.Option("--password", "-p", help="Decryption password")] = None,
    input_file: Annotated[str | None, typer.Option("--input", "-i", help="Input file (default: stdin)")] = None,
    output_file: Annotated[str | None, typer.Option("--output", "-o", help="Output file (default: stdout)")] = None,
    bytes_mode: Annotated[bool, typer.Option("--bytes", help="Use raw bytes mode")] = False,
) -> None:
    """Decrypt data using OpenSSL AES-256-CBC."""
    if password is None:
        password = getpass.getpass("Enter password: ")

    cipher = OpensslAes256Cbc(password)

    try:
        if bytes_mode:
            # Raw bytes mode
            data_bytes = read_input_bytes(input_file)
            decrypted_bytes = cipher.decrypt_bytes(data_bytes)
            write_output_bytes(decrypted_bytes, output_file)
        else:
            # Base64 mode (default) - always work with strings
            data_str = read_input(input_file)
            decrypted_str = cipher.decrypt_base64(data_str)
            write_output(decrypted_str, output_file)
    except ValueError as e:
        typer.echo(f"Decryption failed: {e}", err=True)
        raise typer.Exit(1) from None
