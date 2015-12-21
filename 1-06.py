import lib.xor
from lib.utils import chunks, hamming_distance
import base64
import binascii
from itertools import zip_longest
from functools import partial
from operator import is_not, getitem
import string

filename='challenge-data/6.txt'
possible_key_sizes = range(2, 41)

input_data = None
with open(filename, 'rb') as f:
    input_data = f.read()

# bytes
encrypted = base64.b64decode(input_data)

probabable_keysizes = {}
for key_size in possible_key_sizes:
    blocks = chunks(encrypted, key_size)

    block1 = next(blocks)
    block2 = next(blocks)

    norm_distance = hamming_distance(block1, block2) / key_size

    probabable_keysizes[key_size] = norm_distance

def transpose(iterable: bytes, length) -> bytes:
    transposed = zip_longest(*chunks(iterable, length))
    cleaner = lambda y: filter(partial(is_not, None), y)
    return map(bytes, map(cleaner, transposed))

def check_keysize(key_size):
    keys = []
    for block in transpose(encrypted, key_size):
        keys.append(lib.xor.crack_single_byte(binascii.hexlify(block).decode())[0])

    key = bytes(keys)
    decoded = lib.xor.repeating_key_bytes(encrypted, key)

    return key, decoded

sorted_keysizes = sorted(probabable_keysizes, key = partial(getitem, probabable_keysizes))

for i, keysize in enumerate(sorted_keysizes):
    decoded = check_keysize(keysize)[0].decode()

    if not (set(decoded) - set(string.printable)):
        print(decoded)
