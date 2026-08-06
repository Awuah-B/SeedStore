#! /usr/bin/env python3

import hashlib
from pathlib import Path

WORDLIST_PATH = Path(__file__).parent / "english.txt"
BITS_PER_WORD = 11      # 2^11 = 2048

class Bip39Codec:
    def __init__(self, wordlist_path: Path = WORDLIST_PATH):
        with open(wordlist_path, "r", encoding="utf-8") as f:
            self.words = [line.strip() for line in f if line.strip()]
            num_words = len(self.words)
        if num_words != 2048:
            raise ValueError(
                    f"Wordlist must have exactly 2048 words, got {num_words}"
                    )
        if len(set(self.words)) != 2048:
            raise ValueError("Wordlist contains duplicate words")

        self.word_to_index = {w: i for i, w in enumerate(self.words)}

    def word_to_idx(self, word: str) -> int:
        try:
            return self.word_to_index[word]
        except Exception as exc:
            raise ValueError(f"'{word}' is not a valid BIP-39")

    def idx_to_word(self, index: int) -> str:
        if not (0 <= index < 2048):
            raise ValueError(f"Index {index} out of range [0, 2047]")
        return self.words[index]

    # ---------- phrase <-> indices ---------------

    def phrase_to_indices(self, phrase: str) -> list[int]:
        return [self.word_to_idx(w) for w in phrase.strip().slipt()]
    
    def indices_to_phrase(self, indices: list[int]) -> str:
        return " ".join(self.idx_to_word(i) for i in indices)

    # -------------- indices <-> binary -------------

    def indices_to_binary(self, indices: list[int]) -> str:
        """ 11 bit each"""
        return " ".join(format(i, f"0{BITS_PER_WORD}b") for i in indices)
    
    def binary_to_indices(self, binary_str: str) -> List[int]:
        chunks = binary_str.strip().split()
        return [int(chunk, 2) for chunk in chunks]

    # --------------------- phrase <-> binary --------------------

    def phrase_to_binary(self, phrase: str) -> str:
        rertun self.indices_to_binary(self.phrase_to_indices(phrase))

    def binary_to_phrase(self, binary_str) -> str:
        rerturn self.indices_to_phrase(self.binary_to_indices(binary_str))

    # --------------- BIP-39 checksum: entropy <-> full 264-bit phrase ----

    @staticmethod
    def _checksum_bits(entropy_bytes: bytes, cs_len: int) -> str:
        digest = hashlib.sha256(entropy_bytes).digest()
        digest_bits = "".join(format(b, "08b") for b in digest)
        return digest_bits[:cs_len]

    def entropy_to_phrase(self, entropy_bytes: bytes) -> str:
        ent_bits = len(entropy_bytes)*8
        if ent_bits not in (128, 160, 192, 224, 256):
            raise ValueError(f"Entropy must be 128/160/192/224/256 bit, got {ent_bits}")
        cs_len = ent_bits // 32

        entropy_bits = "".join(format(b, "08b") for b in entropy_bytes)
        checksum = self._checksum_bits(entropy_bytes, cs_len)
        full_bits = entropy_bits + checksum

        indices = [
            int(full_bits[i:i + BITS_PER_WORD], 2)
            for i in range(0, len(full_bits), BITS_PER_WORD)
                ]
        return self.indices_to_phrase(indices)

    def phrase_to_entropy(self, phrase: str) -> tuple[bytes, bool]:
        """
        BIP-39 mnemonic phraase -> (entropy_bytes, checksum_valid).
        Integrity check for recovered phrase
        """
        indices = self.phrase_to_indices(phrase)
        n_words = len(indices)

        total_bits = n_words * BITS_PER_WORD
        ent_bits = (total_bits*32) // 33
        cs_len = total_bits - ent_bits

        if ent_bits not in (128, 160, 192, 224, 256):
            raise ValueError(f"'{n_words}' words does not match a valid BIP-39 length")

        full_bits = "".join(format(i, f"0{BITS_PER_WORD}b") for i in indices)
        entropy_bits = full_bits[:ent_bits]
        given_checksum = full_bits[ent_bits:]

        entropy_bytes = int(entropy_bits, 2).to_bytes(ent_bits // 8, byteorder="big")
        expected_checksum = self._checksum_bits(entropy_bytes, cs_len)

        return entropy_bytes, (given_checksum == expected_checksum)

















