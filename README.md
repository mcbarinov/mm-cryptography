# mm-cryptography

A Python cryptography library providing two independent encryption modules: OpenSSL-compatible AES-256-CBC encryption and Fernet symmetric encryption.

## Overview

This library contains two completely independent encryption modules:

- **OpenSSL AES-256-CBC Module**: Full compatibility with OpenSSL command-line tool
- **Fernet Encryption Module**: Simple symmetric encryption using cryptographically secure methods

Each module can be used independently with its own API, security characteristics, and use cases.

---

# OpenSSL AES-256-CBC Module

## Features

- Full compatibility with OpenSSL command-line tool
- PBKDF2 key derivation with 1,000,000 iterations and SHA-256
- Multiple interfaces: raw bytes and Base64 string APIs

## Quick Start

```python
from mm_cryptography import OpensslAes256Cbc

# Initialize with password
cipher = OpensslAes256Cbc("your_secure_password")

# Encrypt and decrypt strings (Base64 encoded)
encrypted = cipher.encrypt_base64("Hello, World!")
decrypted = cipher.decrypt_base64(encrypted)
print(decrypted)  # "Hello, World!"

# Encrypt and decrypt raw bytes
data = b"Binary data here"
encrypted_bytes = cipher.encrypt_bytes(data)
decrypted_bytes = cipher.decrypt_bytes(encrypted_bytes)
print(decrypted_bytes)  # b"Binary data here"
```

## OpenSSL Compatibility

The `OpensslAes256Cbc` class is fully compatible with OpenSSL's command-line tool:

### Encrypt with Python, decrypt with OpenSSL

```python
from mm_cryptography import OpensslAes256Cbc

cipher = OpensslAes256Cbc("mypassword")
encrypted = cipher.encrypt_base64("Hello OpenSSL!")
print(encrypted)
# Output: Base64 encrypted data
```

```bash
# Decrypt with OpenSSL CLI
echo "U2FsdGVkX1..." | openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000000 -base64 -pass pass:mypassword
# Output: Hello OpenSSL!
```

### Encrypt with OpenSSL, decrypt with Python

```bash
# Encrypt with OpenSSL CLI
echo "Hello Python!" | openssl enc -aes-256-cbc -pbkdf2 -iter 1000000 -salt -base64 -pass pass:mypassword
# Output: U2FsdGVkX1...
```

```python
from mm_cryptography import OpensslAes256Cbc

cipher = OpensslAes256Cbc("mypassword")
decrypted = cipher.decrypt_base64("U2FsdGVkX1...")
print(decrypted)  # "Hello Python!\n"
```

## API Reference

### OpensslAes256Cbc

#### Constructor

```python
OpensslAes256Cbc(password: str)
```

Creates a new cipher instance with the given password.

#### Methods

**`encrypt_bytes(plaintext: bytes) -> bytes`**
- Encrypts raw bytes and returns encrypted bytes with OpenSSL-compatible format

**`decrypt_bytes(encrypted: bytes) -> bytes`**
- Decrypts raw encrypted bytes

**`encrypt_base64(plaintext: str) -> str`**
- Encrypts a UTF-8 string and returns Base64-encoded result with line breaks for OpenSSL compatibility

**`decrypt_base64(b64_encoded: str) -> str`**
- Decodes Base64, decrypts, and returns UTF-8 string (handles base64 with or without line breaks)

#### Constants

- `MAGIC_HEADER = b"Salted__"` - OpenSSL magic header
- `SALT_SIZE = 8` - Salt size in bytes
- `KEY_SIZE = 32` - AES-256 key size
- `IV_SIZE = 16` - AES block size
- `ITERATIONS = 1_000_000` - PBKDF2 iterations
- `HEADER_LEN = 8` - Header length

## Security Notes

- Uses AES-256 in CBC mode with PKCS7 padding
- Key derivation via PBKDF2-HMAC-SHA256 with 1,000,000 iterations
- Cryptographically secure random salt generation for each encryption
- Compatible with OpenSSL's default salt-based encryption format

## Error Handling

The OpenSSL module provides clear error messages for common issues:

- Invalid base64 format
- Wrong password or corrupted data
- Missing OpenSSL salt header
- Invalid encrypted data format

```python
from mm_cryptography import OpensslAes256Cbc

cipher = OpensslAes256Cbc("wrong_password")
try:
    cipher.decrypt_base64("invalid_data")
except ValueError as e:
    print(f"Decryption failed: {e}")
```

---

# Fernet Encryption Module

## Features

- Simple symmetric encryption using cryptographically secure methods
- Built-in key generation utilities
- String-based encryption/decryption interface

## Quick Start

```python
from mm_cryptography import fernet_generate_key, fernet_encrypt, fernet_decrypt

# Generate a key
key = fernet_generate_key()

# Encrypt and decrypt
encrypted = fernet_encrypt(data="Secret message", key=key)
decrypted = fernet_decrypt(encoded_data=encrypted, key=key)
print(decrypted)  # "Secret message"
```

## API Reference

### Fernet Functions

**`fernet_generate_key() -> str`**
- Generates a new Fernet encryption key

**`fernet_encrypt(*, data: str, key: str) -> str`**
- Encrypts string data with Fernet

**`fernet_decrypt(*, encoded_data: str, key: str) -> str`**
- Decrypts Fernet-encrypted data

## Security Notes

- Uses Fernet symmetric encryption (AES-128 in CBC mode with HMAC-SHA256 for authentication)
- Built-in key generation using cryptographically secure random number generation
- Authenticated encryption prevents tampering with encrypted data
- Time-based tokens for additional security (optional)

## Error Handling

The Fernet module handles various error scenarios:

- Invalid key format
- Invalid token format
- Authentication failures (tampered data)
- Expired tokens (if using time-based encryption)

```python
from mm_cryptography import fernet_encrypt, fernet_decrypt
from cryptography.fernet import InvalidToken

try:
    result = fernet_decrypt(encoded_data="invalid_token", key="invalid_key")
except InvalidToken as e:
    print(f"Fernet decryption failed: {e}")
```
