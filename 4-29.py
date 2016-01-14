import lib.sha1
from lib.utils import chunks
import os
import struct
import random

key = None
with open('/usr/share/dict/words', 'rb') as f:
    key = random.choice(f.readlines())

def compute_padding(message):
    message_byte_length = len(message)
    message += b'\x80'
    message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)
    message_bit_length = message_byte_length * 8
    message += struct.pack(b'>Q', message_bit_length)
    return message[message_byte_length:]

def verify(message, sig):
    return lib.sha1.Sha1Hash().update(key + message).digest() == sig

original_message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

sha1_hash = lib.sha1.Sha1Hash()

om_digest = sha1_hash.update(key + original_message).digest()

# attacker controlled stuff starts here

attack_string = b";admin=true"

# length is 20, so split it into the 5 registers (4 bytes each)
a, b, c, d, e = map(lambda x: int.from_bytes(x, 'big'), chunks(om_digest, 4))

possible_key_sizes = set()
with open('/usr/share/dict/words', 'rb') as f:
    possible_key_sizes = set(map(len, f.readlines()))

for key_size in possible_key_sizes:
    some_key = bytes(key_size)
    padding = compute_padding(some_key + original_message)

    # make the SHA-1 state match the one from the original hash
    # TODO: Figure out why padding is needed here when we're doing this
    sha1_hash = lib.sha1.Sha1Hash()
    sha1_hash.update(some_key + original_message + padding)
    sha1_hash._h = a, b, c, d, e

    sha1_hash.update(attack_string)
    digest = sha1_hash.digest()

    attack_message = original_message + padding + attack_string

    # attempt to verify our padding
    if verify(attack_message, digest):
        print("Forged this message:")
        print(attack_message)
        break
else:
    print("Didn't manage to forge the message")
