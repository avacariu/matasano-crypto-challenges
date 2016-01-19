import lib.md4
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
    message += struct.pack(b'<Q', message_bit_length)
    return message[message_byte_length:]

def verify(message, sig):
    return bytes(lib.md4.MD4(key + message)) == sig

original_message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

om_digest = bytes(lib.md4.MD4(key + original_message))
a, b, c, d = struct.unpack('<4I', om_digest)

# attacker controlled stuff starts here

attack_string = b";admin=true"

possible_key_sizes = set()
with open('/usr/share/dict/words', 'rb') as f:
    possible_key_sizes = set(map(len, f.readlines()))

for key_size in possible_key_sizes:
    some_key = bytes(key_size)
    padding = compute_padding(some_key + original_message)

    attack_message = original_message + padding + attack_string

    digest = bytes(lib.md4.MD4(attack_string,
                               len(some_key + attack_message),
                               [a, b, c, d]))

    # attempt to verify our padding
    if verify(attack_message, digest):
        print("Forged this message:")
        print(attack_message)
        break
else:
    print("Didn't manage to forge the message")
