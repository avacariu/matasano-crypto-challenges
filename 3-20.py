from lib.crypto import aes_ctr, random_key
from lib.utils import chunks
import lib.xor
import base64
import binascii
import string
from itertools import zip_longest
from functools import partial
from operator import is_not

plaintexts = []

with open("challenge-data/20.txt") as f:
    plaintexts = f.readlines()

key = random_key()
nonce = 0

ciphertexts = [aes_ctr(key, base64.b64decode(pt), nonce) for pt in plaintexts]
short_ct, *other_cts = sorted(ciphertexts, key=len)
truncated_cts = [ct[:len(short_ct)] for ct in ciphertexts]

concat_ct = b"".join(truncated_cts)
key_size = len(short_ct)

def transpose(iterable: bytes, length) -> bytes:
    transposed = zip_longest(*chunks(iterable, length))
    cleaner = lambda y: filter(partial(is_not, None), y)
    return map(bytes, map(cleaner, transposed))

keys = []
for block in transpose(concat_ct, key_size):
    keys.append(lib.xor.crack_single_byte(binascii.hexlify(block).decode())[0])

key = bytes(keys)
pt = lib.xor.repeating_key_bytes(concat_ct, key)

# not perfect, but close enough
# a better method would be to also check that the full sentence makes sense
# (using nltk), before cracking the next byte
print(pt.decode())
