from lib.crypto import aes_cbc_encrypt, aes_cbc_decrypt
from lib.utils import xor
import os

key = os.urandom(16)

def decrypt(key, ciphertext):
    plaintext = aes_cbc_decrypt(key, ciphertext, iv=key)

    for byte in plaintext:
        if byte > 126:
            raise Exception(plaintext)


random_pt = os.urandom(16*3)
random_ct = aes_cbc_encrypt(key, random_pt, iv=key)

# as the attacker
attack_ct = random_ct[:16] + bytes(16) + random_ct[:16]

# as the receiver
try:
    decrypt(key, attack_ct)
except Exception as e:
    # as the attacker
    attack_pt = e.args[0]

    recovered_key = xor(attack_pt[:16], attack_pt[32:])
    print(key)
    print(recovered_key)

# What's going on?

# first block of attack_pt is E(attack_ct[:16]) ^ key
# third block of attack_pt is E(attack_ct[:16]) ^ 0
#       (since second block of attack_ct was 0)
# so xor the first and last block of attack_pt and you get the key
