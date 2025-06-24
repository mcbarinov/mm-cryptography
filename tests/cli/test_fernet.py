import os

import pytest
from typer.testing import CliRunner

from mm_cryptography.cli.main import app


@pytest.fixture
def runner():
    return CliRunner()


def test_generate_key(runner):
    """Test key generation produces valid key."""
    result = runner.invoke(app, ["fernet", "generate-key"])

    assert result.exit_code == 0
    key = result.stdout.strip()
    # Fernet keys are 44 bytes base64 encoded
    assert len(key) == 44
    assert key.endswith("=")


def test_encrypt_decrypt_with_direct_key(runner, tmp_path):
    """Test encrypt/decrypt cycle with direct key."""
    # Generate key
    key_result = runner.invoke(app, ["fernet", "generate-key"])
    key = key_result.stdout.strip()

    # Create test file
    test_file = tmp_path / "test.txt"
    test_data = "secret message"
    test_file.write_text(test_data)

    encrypted_file = tmp_path / "encrypted.txt"
    decrypted_file = tmp_path / "decrypted.txt"

    # Encrypt
    encrypt_result = runner.invoke(
        app, ["fernet", "encrypt", "--key", key, "--input", str(test_file), "--output", str(encrypted_file)]
    )
    assert encrypt_result.exit_code == 0

    # Decrypt
    decrypt_result = runner.invoke(
        app, ["fernet", "decrypt", "--key", key, "--input", str(encrypted_file), "--output", str(decrypted_file)]
    )
    assert decrypt_result.exit_code == 0

    # Check result
    decrypted_data = decrypted_file.read_text()
    assert decrypted_data == test_data


def test_encrypt_with_key_file(runner, tmp_path):
    """Test encryption with key from file."""
    # Generate key
    key_result = runner.invoke(app, ["fernet", "generate-key"])
    key = key_result.stdout.strip()

    # Save key to file
    key_file = tmp_path / "key.txt"
    key_file.write_text(key)

    # Create test file
    test_file = tmp_path / "test.txt"
    test_file.write_text("test data")

    # Encrypt using key file
    result = runner.invoke(app, ["fernet", "encrypt", "--key-file", str(key_file), "--input", str(test_file)])

    assert result.exit_code == 0
    assert result.stdout  # Should have encrypted output


def test_encrypt_with_env_key(runner, tmp_path):
    """Test encryption with key from environment variable."""
    # Generate key
    key_result = runner.invoke(app, ["fernet", "generate-key"])
    key = key_result.stdout.strip()

    # Set environment variable
    os.environ["TEST_FERNET_KEY"] = key

    try:
        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("env test data")

        # Encrypt using env key
        result = runner.invoke(app, ["fernet", "encrypt", "--key-env", "TEST_FERNET_KEY", "--input", str(test_file)])

        assert result.exit_code == 0
        assert result.stdout
    finally:
        os.environ.pop("TEST_FERNET_KEY", None)


def test_encrypt_no_key_fails(runner, tmp_path):
    """Test that encryption fails without key."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("data")

    result = runner.invoke(app, ["fernet", "encrypt", "--input", str(test_file)])

    assert result.exit_code == 2  # typer.BadParameter


def test_encrypt_multiple_keys_fails(runner, tmp_path):
    """Test that providing multiple key sources fails."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("data")

    result = runner.invoke(app, ["fernet", "encrypt", "--key", "fake_key", "--key-env", "FAKE_ENV", "--input", str(test_file)])

    assert result.exit_code == 2  # typer.BadParameter


def test_decrypt_invalid_key_fails(runner, tmp_path):
    """Test that decryption with wrong key fails."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("gAAAAABh...")  # fake encrypted data

    result = runner.invoke(
        app, ["fernet", "decrypt", "--key", "fake_key_12345678901234567890123456789012", "--input", str(test_file)]
    )

    assert result.exit_code == 1
    assert "Decryption failed" in result.stderr
