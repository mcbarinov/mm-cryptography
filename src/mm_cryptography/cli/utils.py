import sys
from pathlib import Path


def read_input(input_path: str | None) -> str:
    """Read input from file or stdin."""
    if input_path is None:
        return sys.stdin.read()

    return Path(input_path).read_text(encoding="utf-8")


def read_input_bytes(input_path: str | None) -> bytes:
    """Read input as bytes from file or stdin."""
    if input_path is None:
        return sys.stdin.buffer.read()

    return Path(input_path).read_bytes()


def write_output(data: str, output_path: str | None) -> None:
    """Write output to file or stdout."""
    if output_path is None:
        sys.stdout.write(data)
        sys.stdout.flush()
    else:
        Path(output_path).write_text(data, encoding="utf-8")


def write_output_bytes(data: bytes, output_path: str | None) -> None:
    """Write output as bytes to file or stdout."""
    if output_path is None:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        Path(output_path).write_bytes(data)
