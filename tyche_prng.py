from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import time


def increment_counter(counter: bytearray) -> None:
    """Treats a bytearray as an integer (lsb first) and increments it by 1."""
    # If the counter comes back around to 0 again then we've survived the heat death of the Universe
    for i in range(len(counter)):
        if counter[i] != 255:
            counter[i] += 1
            return
        counter[i] = 0


def sha256_hash(to_be_hashed: bytearray) -> bytearray:
    """Convenience wrapper for a SHA256 hash that returns a bytearray."""
    return bytearray(hashlib.sha256(to_be_hashed).digest())


def sha256_hash_all(*args):
    """Convenience wrapper for SHA256 hashing of multiple chunks in separate bytearrays"""
    h = hashlib.sha256()
    for a in args:
        h.update(a)
    return bytearray(h.digest())


class SimpleAES(object):
    """Convenience wrapper for an AES block cipher in CTR mode"""

    def __init__(self):
        # The cryptography package has deprecated different backends but the API still requires one
        self.backend = default_backend()

        # The nonce doesn't need to be secret but it should never be reused with the same key
        self.nonce = sha256_hash(bytearray(str(time.process_time_ns()), 'utf-8'))[:16]

        # This will hold the AES encryptor
        self.encryptor = None

    def update_key(self, new_key: bytearray):
        # Doesn't really matter what nonce is as long as it changes
        increment_counter(self.nonce)

        # The cryptography package seems to require reestablishing everything
        self.encryptor = Cipher(algorithms.AES(new_key), modes.CTR(self.nonce), self.backend).encryptor()

    def encrypt_block(self, block: bytearray) -> bytearray:
        return self.encryptor.update(block)


class EntropyPools(object):
    """
    Maintain pools of entropy a la Fortuna.

    Entropy is added to different pools in a round robin fashion. When entropy is used to reseed a PRNG,
    a different number of pools is used to make attacks more difficult.
    """
    POOL_COUNT = 32
    POOL_BITS = 256
    POOL_BYTES = POOL_BITS // 8

    def __init__(self):
        # As in Fortunat, we maintain 32 pools of entropy.
        # Each pool is 256 bits long and keep them all in a single bytearray.
        self.pools = bytearray(self.POOL_COUNT * self.POOL_BYTES)

        # As new entropy arrives, we add it to each pool in sequence
        self.next_pool = 0

    def add_entropy(self, new_entropy: bytearray):
        """Add new entropy. It will be added to the next pool in the sequence."""
        # Determine where the current pool is in the bytearray and extract it
        start = self.next_pool * self.POOL_BYTES
        end = start + self.POOL_BYTES
        old_entropy = self.pools[start:end]

        # Mix the new entropy with the old entropy pool
        entropy = sha256_hash_all(old_entropy, new_entropy)

        # Reinsert the entropy back into the pool
        self.pools[start:end] = entropy

        # Advance to the next pool
        self.next_pool = (self.next_pool + 1) & (self.POOL_COUNT - 1)

    def get_entropy(self, iteration) -> bytearray:
        """
        Retrieve entropy from the pools. The iteration determines which subset of pools are used.

        As with Fortuna, we use entroy from the first N pools based on the iteration count.
        """
        # The number of pools to use is determined by the least significant but of the current iteration.
        # Pool 0 is used for ever reseed, Pool 1 for ever other reseed, Pool 2 for every 4th reseed, etc..
        bits = iteration | (2 << self.POOL_COUNT)
        number_of_pools = ((1 + (bits ^ (bits - 1))) >> 1) + 1

        # Retrieve the correct number of pools from the front of the pools array.
        end = number_of_pools * self.POOL_BYTES
        return self.pools[:end]


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

        # Maintain pools of entropy
        self.entropy_pools = EntropyPools()

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
            blocks += self.aes.encrypt_block(self.counter)
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
    tprng.reseed(bytearray(b"this is a test"))
    for j in range(4):
        for k in range(10):
            b = tprng.generate_random_blocks(4)
            print(j, k, len(b), b)
        tprng.reseed(bytearray(str(time.process_time_ns()), 'utf-8'))
