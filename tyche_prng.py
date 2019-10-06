# Use the cryptography package for AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Use the standard library's hashlib for SHA256
import hashlib

import os
from queue import Empty, Queue
import resource
import sys
from threading import Thread
import time


# Utility functions

def debug(*args, **kwargs):
    """Just a convenience to log to stderr for debugging."""
    print(*args, file=sys.stderr, **kwargs)


def increment_counter(counter: bytearray) -> None:
    """Treats a bytearray as an integer (lsb first) and increments it by 1."""
    # If the counter comes back around to 0 again then we've survived the heat
    # death of the Universe.
    for i in range(len(counter)):
        if counter[i] != 255:
            counter[i] += 1
            return
        counter[i] = 0


def sha256_hash(to_be_hashed: bytearray) -> bytearray:
    """Convenience wrapper for a SHA256 hash that returns a bytearray."""
    return bytearray(hashlib.sha256(to_be_hashed).digest())


def sha256_hash_all(*args):
    """Convenience wrapper for SHA256 hashing of separate chunks."""
    h = hashlib.sha256()
    for a in args:
        h.update(a)
    return bytearray(h.digest())


class SimpleAES:
    """Convenience wrapper for an AES block cipher in CTR mode"""

    def __init__(self):
        # The cryptography package has deprecated different backends but the
        # API still requires one
        self.backend = default_backend()

        # The nonce doesn't need to be secret but it should never be reused
        # with the same key
        self.nonce = sha256_hash(bytearray(str(time.process_time_ns()),
                                           'utf-8'))[:16]

        # This will hold the AES encryptor
        self.encryptor = None

    def update_key(self, new_key: bytearray):
        # Doesn't really matter what nonce is as long as it changes
        increment_counter(self.nonce)

        # The cryptography package seems to require reestablishing everything
        self.encryptor = Cipher(algorithms.AES(new_key), modes.CTR(self.nonce),
                                self.backend).encryptor()

    def encrypt_block(self, block: bytearray) -> bytearray:
        return self.encryptor.update(block)


class EntropyPools:
    """
    Maintain pools of entropy a la Fortuna.

    Entropy is added to different pools in a round robin fashion for each
    entropy source. When entropy is used to reseed a PRNG, a different number
    of pools is used to make attacks more difficult.
    """
    POOL_COUNT = 32     # Must be a power of 2
    POOL_BITS = 256
    POOL_BYTES = POOL_BITS // 8

    def __init__(self):
        # As in Fortuna we maintain 32 pools of entropy.
        # All pools are 256 bits long and kept in a single bytearray.
        self.pools = bytearray(self.POOL_COUNT * self.POOL_BYTES)

        # As entropy arrives, add it to each pool in sequence for each source.
        self.next_pool = {}

        # Number of times entropy has been requested via get_entropy().
        self.request_count = 0

    def add_entropy(self, entropy_source: str, new_entropy: bytearray):
        """Add new entropy to the next pool in the sequence for this source."""
        # Each source gets its own index into the poos
        current = self.next_pool.get(entropy_source, 0)

        # Determine where the current pool is in the bytearray and extract it
        start = current * self.POOL_BYTES
        end = start + self.POOL_BYTES
        old_entropy = self.pools[start:end]

        # Mix the new entropy with the old entropy pool.
        entropy = sha256_hash_all(old_entropy, new_entropy)

        # Reinsert the entropy back into the pool.
        self.pools[start:end] = entropy

        # Advance to the next pool
        self.next_pool[entropy_source] = (current + 1) & (self.POOL_COUNT - 1)

    def get_entropy(self) -> bytearray:
        """
        Retrieve entropy from the pools. The iteration determines which subset of pools are used.

        As with Fortuna, we use entropy from the first N pools based on the iteration count.
        """
        # The number of pools to use is determined by the least significant but of the current iteration.
        # Pool 0 is used for ever reseed, Pool 1 for ever other reseed, Pool 2 for every 4th reseed, etc..
        self.request_count += 1
        bits = self.request_count | (2 << self.POOL_COUNT)
        number_of_pools = (1 + (bits ^ (bits - 1))) >> 1

        # Retrieve the correct number of pools from the front of the pools array.
        end = number_of_pools * self.POOL_BYTES
        return self.pools[:end]


# Entropy generator functions. Each entropy generator will run in its own thread
# for simplicity. Each generator gets its own small queue to provide information
# back to the entropy accumulator. The function should loop forever and can try
# to generate entropy as frequently as it wants to. Queue writes will block
# until the generator's policy decides to receive more entropy.

class EntropyGenerator(Thread):
    """'Abstract' superclass for entropy generators"""

    def __init__(self, name: str):
        Thread.__init__(self)
        self.name = name
        self.queue = Queue(1)

    def send_entropy(self, entropy: bytearray):
        self.queue.put(entropy)

    def get_entropy(self, block: bool) -> bytearray:
        entropy = None
        try:
            entropy = self.queue.get(block=block)
        except Empty:
            pass
        return entropy

    def collect_entropy(self):
        pass

    def run(self):
        """Excecute entropy generation and catch exceptions."""
        try:
            self.collect_entropy()
        except KeyboardInterrupt:
            # Don't dump a stack trace when the user hits CTRL-C
            pass
        return


class EntropyFromExecutionJitter(EntropyGenerator):
    def __init__(self):
        EntropyGenerator.__init__(self, "jitter")

    def collect_entropy(self):
        """
        Execute some code that is likely to take different amounts of time to run
        on different passes.

        Create a list large enough to span multiple pages of memory and transform
        it along with some conditional operations to potentially take advantage
        of speculative execution in the CPU.
        """
        length = resource.getpagesize() * 5
        array = list(range(length))
        while True:
            start = time.perf_counter_ns()
            # meaningless operation to take time
            array = [x + 2 if x & 1 == 0 else x + 1 for x in array]
            end = time.perf_counter_ns()
            self.send_entropy(bytearray(str(end - start), 'utf-8'))


class EntropyFromUsage(EntropyGenerator):
    def __init__(self):
        EntropyGenerator.__init__(self, "usage")

    def collect_entropy(self):
        while True:
            x = resource.getrusage(resource.RUSAGE_SELF)
            s = str([x.ru_utime, x.ru_stime, x.ru_maxrss,
                     x.ru_minflt, x.ru_nvcsw, x.ru_nivcsw])
            stats = bytearray(s, 'utf-8')
            self.send_entropy(stats)


class TychePRNG:
    """
    A implementation of a Fortuna-like PRNG simplified for this use case.

    A more general implementation has to be able to deliver odd numbers of bytes, check on limits for
    request lengths, etc...  This is not needed here since we will always use this to get a fixed number
    of random blocks.

    Fortuna is the Roman goddess of fortune. Tyche is the Greek goddess of fortune.
    """

    # Number of block requests before reseeding from entropy pool.
    # Must be a power of 2.
    RESEED_INTERVAL = 2 << 10

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

        # Entropy generators
        self.generators = []

        # Number of blocks produced
        self.reseed_counter = 0

    def start(self):
        """Start up separate threads for each entropy source"""
        self.generators.append(EntropyFromExecutionJitter())
        self.generators.append(EntropyFromUsage())
        # Add more entropy sources here

        for t in self.generators:
            t.daemon = True
            t.start()

    def poll_entropy_sources(self) -> int:
        count = 0
        for g in self.generators:
            entropy = g.get_entropy(True)
            if entropy is not None:
                self.entropy_pools.add_entropy(g.name, entropy)
                count += 1
        return count

    def reseed(self, count):
        """Seed with additional entropy"""

        # Get some entropy from the sources
        i = 0
        while i < count:
            i += self.poll_entropy_sources()

        # Mix the old key with some new entropy
        self.key = sha256_hash(self.key + self.entropy_pools.get_entropy())
        increment_counter(self.counter)
        self.seeded = True
        self.aes.update_key(self.key)

    def _generate_blocks(self, num_blocks: int) -> bytearray:
        """Generates random blocks using the same key. Internal!"""
        if not self.seeded:
            self.reseed(1000)

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

        # AES is good but it will result in no collisions for too long.
        # So after a number of requests, add some more entropy.
        self.reseed_counter += 1
        if self.reseed_counter & (self.RESEED_INTERVAL - 1) == 0:
            self.reseed(1)

        return blocks


if __name__ == "__main__":
    try:
        tprng = TychePRNG()
        tprng.start()
        while True:
            random_bytes = tprng.generate_random_blocks(64)
            os.write(1, random_bytes)
    except KeyboardInterrupt:
        # Don't dump a stack trace when the user hits CTRL-C
        sys.exit(1)
