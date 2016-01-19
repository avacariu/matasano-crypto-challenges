from lib.random import MersenneTwister
from lib.utils import chunks, xor
import os
import random
import time


def rand_8bit(key: int):
    twister = MersenneTwister(key)
    while True:
        random_32bit = twister.extract_number()
        for i in range(4):
            yield (random_32bit >> (8*i)) & 0xFF

def encrypt(key: int, plaintext):
    return bytes(pt ^ k for (pt, k) in zip(plaintext, rand_8bit(key)))

# to "crack" the cipher, we'll just brute force it; it's only 16 bits.

# "oracle" computations
chosen_pt = b"A" * 14
random_prefix = os.urandom(random.randint(0, 10))
key = int.from_bytes(os.urandom(2), byteorder='big', signed=False)
ct = encrypt(key, random_prefix + chosen_pt)

# "attacker" computations
prefix_len = len(ct) - len(chosen_pt)
key_stream = xor(ct[prefix_len:], chosen_pt)

for possible_key in range(2**16):
    generator = rand_8bit(possible_key)
    guess_kstream = bytes(next(generator) for i in range(len(ct)))

    if guess_kstream[prefix_len:] == key_stream:
        print(possible_key)
        assert key == possible_key
        break

# do basically the same but for a timestamp seed

def gen_token():
    seed = int(time.time())
    generator = rand_8bit(seed)
    token = bytes(next(generator) for i in range(16))

    return token

def token_seeded_from_time(token, seconds_ago=300):
    """
    seconds_ago: the amount of seconds in the past to check for a seed.
                 set this to a minute before the token was generated
    """
    current_time = int(time.time())

    for i in range(seconds_ago):
        seed = current_time - i

        generator = rand_8bit(seed)
        guess_token = bytes(next(generator) for i in range(16))

        if guess_token == token:
            return True

    return False
