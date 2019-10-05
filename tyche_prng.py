from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import time


def increment_counter(counter: bytearray) -> None:
    """Treats a bytearray as an integer (lsb first) and increments it by 1."""
    # If the counter comes back around to 0 again then we've survived the heat death of the Universe
    for i in range(len(counter)):
        if counter[i] != 255:
            counter[i] = counter[i] + 1
            return
        counter[i] = 0


def sha256_hash(bytes: bytearray) -> bytearray:
    """Convenience wrapper for a SHA256 hash that returns a bytearray."""
    return bytearray(hashlib.sha256(bytes).digest())


class SimpleAES(object):
    """Convenience wrapper for an AES block cipher in CTR mode"""

    def __init__(self):
        # The cryptography package has deprecated different backends but the API still requires one
        self.backend = default_backend()

        # The nonce doesn't need to be secret but it should never be reused with the same key
        self.nonce = sha256_hash(bytearray(str(time.process_time_ns()), 'utf-8'))[:16]

    def update_key(self, new_key: bytearray):
        # Doesn't really matter what nonce is as long as it changes
        increment_counter(self.nonce)

        # The cryptography package seems to require reestablishing everything
        self.encryptor = Cipher(algorithms.AES(new_key), modes.CTR(self.nonce), self.backend).encryptor()

    def encrypt_block(self, block: bytearray) -> bytearray:
        return self.encryptor.update(block)


class TychePRNG(object):
    """
    A implementation of a Fortuna-like PRNG simplified for this use case.

    A more general implementation has to be able to deliver odd numbers of bytes, check on limits for
    request lengths, etc...  This is not needed here since we will always use this to get a fixed number
    of random blocks.

    Fortuna is the Roman goddess of fortune. Tyche is the Greek goddess of fortune.
    """

    def __init__(self):
        # 256-bit block cipher key (starts zeroed out)
        self.key = bytearray(32)

        # 128-bit counter kept in an int
        self.counter = bytearray(16)

        # Indicates if we're already seeded (cheaper than testing counter)
        self.seeded = False

        # Setup the cryptopgraphy package for AES in CTR mode
        self.aes = SimpleAES()

    def reseed(self, additional_seed: bytearray):
        """Seed with additional entropy"""

        # Mix the old key with some new entropy
        self.key = sha256_hash(self.key + additional_seed)
        increment_counter(self.counter)
        self.seeded = True
        self.aes.update_key(self.key)

    def _generate_blocks(self, num_blocks: int) -> bytearray:
        """Generates random blocks using the same key. Not to be called directly."""
        if not self.seeded:
            # XXX - block until we have been seeded?
            pass
        # We won't check num_blocks since we will call it with a reasonable value
        blocks = bytearray()
        for i in range(num_blocks):
            blocks = blocks + self.aes.encrypt_block(self.counter)
            increment_counter(self.counter)

        return blocks

    def generate_random_blocks(self, num_blocks: int) -> bytearray:
        """Generates random blocks and replaces the key for forward secrecy."""
        blocks = self._generate_blocks(num_blocks)

        # Change the key to prevent compromising of these blocks
        self.key = self._generate_blocks(2)
        self.aes.update_key(self.key)

        return blocks


if __name__ == "__main__":
    tprng = TychePRNG()
    tprng.reseed(b"this is a test")
    for j in range(4):
        for i in range(10):
            b = tprng.generate_random_blocks(4)
            print(j, i, len(b), b)
        tprng.reseed(bytearray(str(time.process_time_ns()), 'utf-8'))