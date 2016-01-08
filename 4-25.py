from lib.crypto import aes_ecb_decrypt, aes_ctr
from lib.utils import xor
import base64
import os

original_key = b"YELLOW SUBMARINE"
with open("challenge-data/25.txt") as f:
    original_ct = base64.b64decode(f.read())

plaintext = aes_ecb_decrypt(original_key, original_ct)

random_key = os.urandom(16)

ctr_ct = aes_ctr(random_key, plaintext)

def edit(ciphertext, key, offset, newtext):
    ct_block = aes_ctr(key, newtext, counter=offset)
    return ciphertext[:offset*16] + ct_block + ciphertext[offset*16 + 16:]

def api(offset, newtext):
    return edit(ctr_ct, random_key, offset, newtext)

# ciphertext = E(Counter) XOR plaintext
# So if we set plaintext to 00000000..., we get E(counter)
# and then plaintext = E(counter) ^ ciphertext

num_blocks = len(ctr_ct) // 16

null_ct = b""

for offset in range(num_blocks):
    e_counter = api(offset, bytes(16))
    null_ct += e_counter[offset*16 : offset*16 + 16]

decrypted = xor(null_ct, ctr_ct)
print(decrypted.decode())
