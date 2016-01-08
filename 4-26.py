from lib.crypto import pkcs7, aes_ctr
from lib.utils import xor
import urllib

import os

key = os.urandom(16)

def prepare(plaintext: bytes) -> bytes:
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

    pt = prefix + urllib.parse.quote(plaintext).encode() + suffix

    return aes_ctr(key, pt)

def isadmin(key: bytes, ciphertext: bytes) -> bool:
    plaintext = aes_ctr(key, ciphertext)

    print(plaintext)
    for key, val in map(lambda x: x.split(b"="), plaintext.split(b";")):
        if key == b"admin" and val == b"true":
            return True

    return False

ct = bytearray(prepare(b'A' * 16))
block_of_encrypted_As = ct[32:48]
keystream_for_block = xor(block_of_encrypted_As, b'A'*16)

target_pt = pkcs7(b";admin=true;")
ct[32:48] = xor(keystream_for_block, target_pt)

print(isadmin(key, bytes(ct)))
