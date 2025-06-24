import pytest
from typer.testing import CliRunner

from mm_cryptography.cli.main import app


@pytest.fixture
def runner():
    return CliRunner()


def test_encrypt_decrypt_base64_mode(runner, tmp_path):
    """Test encrypt/decrypt cycle in base64 mode."""
    password = "test_password"
    test_data = "secret message"

    # Create test file
    test_file = tmp_path / "test.txt"
    test_file.write_text(test_data)

    encrypted_file = tmp_path / "encrypted.txt"
    decrypted_file = tmp_path / "decrypted.txt"

    # Encrypt
    encrypt_result = runner.invoke(
        app, ["openssl", "encrypt", "--password", password, "--input", str(test_file), "--output", str(encrypted_file)]
    )
    assert encrypt_result.exit_code == 0

    # Decrypt
    decrypt_result = runner.invoke(
        app, ["openssl", "decrypt", "--password", password, "--input", str(encrypted_file), "--output", str(decrypted_file)]
    )
    assert decrypt_result.exit_code == 0

    # Check result
    decrypted_data = decrypted_file.read_text()
    assert decrypted_data == test_data


def test_encrypt_decrypt_bytes_mode(runner, tmp_path):
    """Test encrypt/decrypt cycle in bytes mode."""
    password = "test_password"
    test_data = b"binary secret data \x00\x01\x02"

    # Create test file with binary data
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(test_data)

    encrypted_file = tmp_path / "encrypted.bin"
    decrypted_file = tmp_path / "decrypted.bin"

    # Encrypt
    encrypt_result = runner.invoke(
        app, ["openssl", "encrypt", "--password", password, "--bytes", "--input", str(test_file), "--output", str(encrypted_file)]
    )
    assert encrypt_result.exit_code == 0

    # Decrypt
    decrypt_result = runner.invoke(
        app,
        [
            "openssl",
            "decrypt",
            "--password",
            password,
            "--bytes",
            "--input",
            str(encrypted_file),
            "--output",
            str(decrypted_file),
        ],
    )
    assert decrypt_result.exit_code == 0

    # Check result
    decrypted_data = decrypted_file.read_bytes()
    assert decrypted_data == test_data


def test_encrypt_to_stdout(runner, tmp_path):
    """Test encryption with output to stdout."""
    password = "test_password"
    test_data = "stdout test"

    test_file = tmp_path / "test.txt"
    test_file.write_text(test_data)

    # Encrypt to stdout
    result = runner.invoke(app, ["openssl", "encrypt", "--password", password, "--input", str(test_file)])

    assert result.exit_code == 0
    assert result.stdout  # Should have encrypted output
    assert result.stdout != test_data  # Should be encrypted


def test_decrypt_wrong_password_fails(runner, tmp_path):
    """Test that decryption with wrong password fails."""
    correct_password = "correct_password"
    wrong_password = "wrong_password"
    test_data = "test data"

    test_file = tmp_path / "test.txt"
    test_file.write_text(test_data)

    encrypted_file = tmp_path / "encrypted.txt"

    # Encrypt with correct password
    encrypt_result = runner.invoke(
        app, ["openssl", "encrypt", "--password", correct_password, "--input", str(test_file), "--output", str(encrypted_file)]
    )
    assert encrypt_result.exit_code == 0

    # Try to decrypt with wrong password
    decrypt_result = runner.invoke(app, ["openssl", "decrypt", "--password", wrong_password, "--input", str(encrypted_file)])

    assert decrypt_result.exit_code == 1
    assert "Decryption failed" in decrypt_result.stderr


def test_decrypt_invalid_data_fails(runner, tmp_path):
    """Test that decryption of invalid data fails."""
    password = "test_password"

    # Create file with invalid encrypted data
    invalid_file = tmp_path / "invalid.txt"
    invalid_file.write_text("invalid_encrypted_data")

    result = runner.invoke(app, ["openssl", "decrypt", "--password", password, "--input", str(invalid_file)])

    assert result.exit_code == 1
    assert "Decryption failed" in result.stderr


def test_encrypt_prompt_password(runner, tmp_path):
    """Test password prompt when no password provided."""
    test_data = "prompt test"

    test_file = tmp_path / "test.txt"
    test_file.write_text(test_data)

    # Encrypt without --password flag (should prompt)
    result = runner.invoke(
        app,
        ["openssl", "encrypt", "--input", str(test_file)],
        input="prompt_password\nprompt_password\n",  # Enter password twice
    )

    assert result.exit_code == 0
    assert result.stdout  # Should have encrypted output
