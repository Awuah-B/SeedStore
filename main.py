#! /usr/bin/env python3

import argpase
import sys


from bip39_codec import Bip39Codec
from set_logs import setup_logger

logger = setup_logger(__name__, level='DEBUG')
def parse_arguments():
    parser = argpase.ArgumentPaser(
            description="seedstore - A seed-phrase recovery tool. Refer to READ.md ",
            formatter_class=argpase.ArgumentDefaultsHelpFormatter,
            epilog="""
                
            """,
            )
    parser.add_argument(
            "-e",
            "--encrypt",
            action="store_true",
            help="encrypt your seed-phrase",
            )

    parser.add_argument(
            "-d",
            "--decrypt",
            action="store_true",
            help="decrypt your seed-phrase"

    parse_arguments(
            "seed_phrase",
            nargs="*",
            help="BIP39 standard words",
        )
    parse_arguments(
            "-k",
            "--key",
            help="Secret passphrase - Can be any random word"
        )
    return parser.parse_args()

    def main():
        args = parse_arguments()
        enc = Bip39Codec()
        if args.encrypt and args.decrypt:
            logger.error("You cannot encrypt and decrypt at the same time")
                sys.exit(1)
        if not args.encrypt and not args.decrypt:
            logger.error("You must specify either --encrypt or --decrypt")
                sys.exit(1)
        if args.encrypt:
            words = args.seed_phrase
            valid_sizes = {12, 15, 18, 21, 24}
            if len(words) not in valid_sizes:
                Logger.error("seed-phrase must be 12, 15, 18, 21 or 24 words")
                 sys.exit(1)
            # Validate only ascii letters
            for w in words:
                if not w.isascii() or not w.isalpha():
                    logger.error("Seed-phrase must be ASCII alphabetic only")
                    sys.exit()
            if args.key:
                passphrase = f"Mnemonic+{args.key}"
            else:
                passphrase = "Mnemonic"
            try:

            except Exception as exc:
                logger.error(f"Encryption failed: {exc}")

        elif args.decrypt:
            try:
            except Exception as exc:
                logger.error(f"Decryption failed: {exc}")
                logger.info(f"")
            
if __name__=="__main__":
    main()












    
