#! /usr/bin/env python3

import sys
import argparse
import pyperclip

from src import Bip39Codec, encrypt_entropy, decrypt_entropy
from set_logs import setup_logger

logger = setup_logger(__name__, level='DEBUG')


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="seedstore - A seed-phrase recovery tool.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-e",
        "--encrypt",
        action="store_true",
        help="Encrypt a BIP-39 seed phrase",
    )

    parser.add_argument(
        "-d",
        "--decrypt",
        action="store_true",
        help="Decrypt a previously encrypted blob",
    )

    parser.add_argument(
        "seed_phrase",
        nargs="*",
        help="BIP39 standard words (provide when encrypting)",
    )

    parser.add_argument(
        "-k",
        "--key",
        help="Secret passphrase (optional)",
    )

    parser.add_argument(
        "-b",
        "--blob",
        help="Encrypted blob (base64 urlsafe) when decrypting",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()
    codec = Bip39Codec()

    if args.encrypt and args.decrypt:
        logger.error("You cannot encrypt and decrypt at the same time")
        sys.exit(1)

    if not args.encrypt and not args.decrypt:
        logger.error("You must specify either --encrypt or --decrypt")
        sys.exit(1)

    if args.encrypt:
        words = args.seed_phrase or []
        valid_sizes = {12, 15, 18, 21, 24}
        if len(words) not in valid_sizes:
            logger.error("seed-phrase must be 12, 15, 18, 21 or 24 words")
            sys.exit(1)

        # Validate only ascii letters
        for w in words:
            if not w.isascii() or not w.isalpha():
                logger.error("Seed-phrase must be ASCII alphabetic only")
                sys.exit(1)

        passphrase = f"Mnemonic+{args.key}" if args.key else "Mnemonic"

        try:
            phrase = " ".join(words)
            entropy_bytes, checksum_ok = codec.phrase_to_entropy(phrase)
            if not checksum_ok:
                logger.error("Provided seed phrase failed checksum validation")
                sys.exit(1)
            blob = encrypt_entropy(entropy_bytes, passphrase)
            pyperclip.copy(blob)
            logger.info("Blod copied to clipboard")
        except Exception as exc:
            logger.error(f"Encryption failed: {exc}")
            sys.exit(1)

    elif args.decrypt:
        if not args.blob:
            logger.error("No encrypted blob provided; use -b/--blob to supply it")
            sys.exit(1)

        passphrase = f"Mnemonic+{args.key}" if args.key else "Mnemonic"
        try:
            entropy = decrypt_entropy(args.blob, passphrase)
            phrase = codec.entropy_to_phrase(entropy)

            # Verify checksum and that entropy round-trips correctly.
            recovered, checksum_ok = codec.phrase_to_entropy(phrase)
            if not checksum_ok or recovered != entropy:
                logger.error("Decrypted blob failed BIP-39 checksum/roundtrip verification")
                sys.exit(1)

            print(phrase)
        except Exception as exc:
            logger.error(f"Decryption failed: {exc}")
            sys.exit(1)


if __name__ == "__main__":
    main()












    
