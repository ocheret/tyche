import os
import secrets
import sys

# Generate and write chunks for efficiency
CHUNK_SIZE = 64

def cat_dev_random():
    """Write random bytes to stdout using the secrets package."""
    while True:
        random_byte_string = secrets.token_bytes(CHUNK_SIZE)
        os.write(sys.stdout.fileno(), random_byte_string)

if __name__ == "__main__":
    try:
        cat_dev_random()
    except KeyboardInterrupt:
        # Don't dump a stack trace when the user hits CTRL-C
        sys.exit(1)
