# SeedStore

SeedStore is a simple BIP-39 seed phrase recovery and encrypted storage utility.

It validates BIP-39 mnemonic phrases, converts them to entropy, encrypts the entropy with a passphrase-derived key, and can decrypt previously encrypted blobs back into a valid seed phrase.

## Features

- Validate BIP-39 seed phrases of 12, 15, 18, 21, or 24 words
- Encrypt raw mnemonic entropy using AES-GCM
- Derive encryption keys using scrypt with high cost parameters
- Decrypt encrypted blobs and verify the recovered phrase with BIP-39 checksum
- Copy encrypted blobs to the clipboard automatically on encryption
- Structured JSON-style logging for easier debugging

## Requirements

- Python 3.11+ (or a modern Python 3 version)
- `cryptography`
- `pyperclip`

The repository includes a `requirements.txt` file for easy installation.

## Installation

```bash
python3 -m pip install -r requirements.txt
```

## Usage

Run `main.py` from the project root.

### Encrypt a seed phrase

```bash
python3 main.py --encrypt legal winner thank year wave sausage worth useful legal winner thank yellow
```

- The tool expects a valid BIP-39 seed phrase of 12, 15, 18, 21, or 24 words.
- The encrypted output blob is copied to the clipboard automatically.
- Use `-k` / `--key` to include an optional secret passphrase.

### Decrypt an encrypted blob

```bash
python3 main.py --decrypt -b <encrypted_blob_here>
```

- The decrypted seed phrase is printed to standard output.
- Use `-k` / `--key` if the blob was encrypted with a passphrase.

## Encryption format

Encrypted blobs are JSON objects encoded with URL-safe base64. The JSON includes:

- `v`: version
- `kdf`: key derivation function (`scrypt`)
- `kdf_params`: scrypt parameters
- `salt`: base64-encoded salt
- `nonce`: base64-encoded AES-GCM nonce
- `ciphertext`: base64-encoded encrypted entropy

## Project structure

- `main.py` — CLI entrypoint for encryption and decryption
- `set_logs.py` — logger setup with JSON-formatted output
- `src/bip39_codex.py` — BIP-39 phrase and entropy conversion utilities
- `src/seed_encryption.py` — scrypt key derivation and AES-GCM encryption/decryption
- `src/english.txt` — BIP-39 English word list

## Notes

- This tool is intended as a recovery utility and proof of concept. It is not a full wallet manager.
- Keep your passphrase and encrypted blobs safe.
- Do not use the tool with untrusted or unknown seed
