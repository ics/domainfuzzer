import os
import random
import binascii

__version__ = '0.0.1'


def random_str(length=None):
    """Generate a random string of length"""
    if not length:
        length = random.choice(range(42))
    return binascii.hexlify(os.urandom(length)).decode()
