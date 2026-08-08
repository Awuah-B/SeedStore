#! /usr/bin/env python3

import os
import json
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

#--- scrypt parameters ------
# n: CPU/memory cost (must be power of 2). r: block size. p: parallelism.
# These values (n=2^17, r=8, p=1) need ~128MB RAM and a fraction of a second
# Deliberately expensive enough to slow down brute-force attempts

SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32  # 256-bit AES key
SALT_LEN = 16
NONCE_LEN = 12

SUPPORTED_KDFS = {"scrypt"}
SUPPORTED_VERSIONS = {1}

MIN_SCRYPT_N = 2 ** 10
MAX_SCRYPT_N = SCRYPT_N
MAX_SCRYPT_R = SCRYPT_R
MAX_SCRYPT_P = SCRYPT_P


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """passphrase + salt -> 256-bit AES key via scrypt."""
    maxmem = 132 * SCRYPT_N * SCRYPT_R
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_LEN,
        maxmem=maxmem,
    )


def encrypt_entropy(entropy_bytes: bytes, passphrase: str) -> str:
    """Encrypt raw seed entropy under a passphrase-derived key."""
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(passphrase, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, entropy_bytes, associated_data=None)

    blob = {
        "v": 1,
        "kdf": "scrypt",
        "kdf_params": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    return base64.urlsafe_b64encode(json.dumps(blob).encode()).decode()

def _validate_kdf_params(params: dict) -> None:
    """Reject kdf_params that are malformed or outside the allowed ranges."""
    if not isinstance(params, dict):
        raise ValueErrorr("Malformed blob: kdf_params must be an object")

    n, r, p = params.get("n"), params.get("r"), params.get("p")
    if not all(isinstance(x, int) and not isinstance(x, bool) for x in (n, r, p)):
        raise ValueError("Malformed blob: kdf_params must contain integers n, r, p")

    if n <= 0 or (n & (n - 1)) != 0 or n < MIN_SCRYPT_N or n > MAX_SCRYPT_N:
        raise ValueError(f"Malformed blob: kdf_params.n must be a power of 2 between {MIN_SCRYPT_N} and {MAX_SCRYPT_N}")

    if not ( 0 < r <= MAX_SCRYPT_R and 0 < p <= MAX_SCRYPT_P):
        raise ValueError(f"Malformed blob: kdf_params.r and kdf_params.p must be positive integers within acceptable range")

    

def decrypt_entropy(blob_str: str, passphrase: str) -> bytes:
    blob = json.loads(base64.urlsafe_b64decode(blob_str.encode()))

    version = blob.get("v")
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported blob version: {version!r}")

    kdf = blob.get("kdf")
    if kdf not in SUPPORTED_KDFS:
        raise ValueError(f"Unsupported KDF: {kdf!r}")

    try:
        salt = base64.b64decode(blob["salt"])
        nonce = base64.b64decode(blob["nonce"])
        ciphertext = base64.b64decode(blob["ciphertext"])
        params = blob["kdf_params"]

    except KeyError as e:
        raise ValueError(f"Malformed blob: missing key {e}")

    _validate_kdf_params(params)

    key = hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=params["n"],
        r=params["r"],
        p=params["p"],
        dklen=KEY_LEN,
        maxmem=132 * params["n"] * params["r"],
    )

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag:
        raise ValueError(
            "Decryption failed: wrong passphrase, or the stored blob was corrupted/tampered with"
        )
















