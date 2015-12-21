from lib.crypto import pkcs7, aes_cbc_encrypt, aes_cbc_decrypt
from lib.utils import xor
import urllib

import os

key = os.urandom(16)

def prepare(plaintext: bytes) -> bytes:
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

    pt = prefix + urllib.parse.quote(plaintext).encode() + suffix


    padded = pkcs7(pt, length=16)

    return aes_cbc_encrypt(key, padded)

def isadmin(key: bytes, ciphertext: bytes) -> bool:
    plaintext = aes_cbc_decrypt(key, ciphertext)

    print(plaintext)
    for key, val in map(lambda x: x.split(b"="), plaintext.split(b";")):
        if key == b"admin" and val == b"true":
            return True

    return False

target_pt = pkcs7(b";admin=true;")
ct = bytearray(prepare(b'A'*16))
block_we_flip = ct[16:32]

# idea: we need to flip the AAAAAAs to be ;admin=true;, so we xor it in the
# plaintext and then we xor the result with the previous block in the
# ciphertext. This way, when it gets decrypted, the previous block is
# garbage, but the flipped bits get flipped in the decrypted AAAAAs to flip
# them to ;admin=true;
flip_by = xor(target_pt, b'A'*16)
flipped_block = xor(block_we_flip, flip_by)

ct[16:32] = flipped_block

print(isadmin(key, bytes(ct)))
