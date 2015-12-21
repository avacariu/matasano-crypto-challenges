from lib.crypto import aes_ecb_encrypt, pkcs7, detect_ecb_cbc
from lib.utils import pairwise, chunks
import sys
import os
import base64
import random
import itertools
import string

key = os.urandom(16)
alphabet = string.printable
random_prefix = os.urandom(random.randint(1,500))


def encryption_oracle(plaintext: bytes):
    after = ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
             "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
             "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
             "YnkK")

    pt = random_prefix + plaintext + base64.b64decode(after)
    padded = pkcs7(pt)

    return aes_ecb_encrypt(key, padded)


# discover blocksize by seeing by how much the ciphertext lengths gets
# bumped up
blocksize = 0
ct_len = len(encryption_oracle(b''))

for i in range(1, 1000):
    ct = encryption_oracle(b'A'*i)
    if len(ct) > ct_len:
        blocksize = len(ct) - ct_len
        break

mode = detect_ecb_cbc(encryption_oracle, blocksize)

# discover the length of the hidden text by encrypting an increasing number
# of identical bytes; once we have two blocks that are identical, we know
# that the hidden text begins right after the second block
hidden_text_length = 0
def exist_identical_blocks(ciphertext):

    for x, y in pairwise(chunks(ciphertext, blocksize)):
        if x == y:
            return True, x

    return False

ct_block = None
necessary_prefix_length = 0
for i in itertools.count(1):
    ct = encryption_oracle(bytes(b'A' * i))
    exist = exist_identical_blocks(ct)
    if exist:
        check_alternatives = []
        for b in alphabet.encode():
            possible_byte = b.to_bytes(length=1, byteorder="big")
            alt_ct = encryption_oracle(possible_byte*i)
            check_alternatives.append(exist_identical_blocks(alt_ct))

        if all(check_alternatives):
            ct_block = exist[1]
            necessary_prefix_length = i
            break
else:
    print("didn't find hidden text length")
    sys.exit(1)

htl_start = ct.find(ct_block*2) + 2*blocksize
hidden_text_length = len(ct) - htl_start

guess_plaintext = bytearray(b'A' * hidden_text_length)
htl = hidden_text_length

# ciphertext with the first byte of the output encoded as the last byte
for i in range(1, hidden_text_length+1):

    target_ct = encryption_oracle(b'A'*necessary_prefix_length + b'A' * (htl - i))

    for b in alphabet.encode():
        possible_byte = b.to_bytes(length=1, byteorder="big")
        guess = bytes(guess_plaintext[1:] + possible_byte)

        ct = encryption_oracle(b'A'*necessary_prefix_length + guess)

        if ct[htl_start : htl_start + htl-1] == target_ct[htl_start : htl_start + htl-1]:
            guess_plaintext.append(b)
            guess_plaintext.pop(0)
            break

    else:
        print("Didn't find the last byte\n")
        break

print(guess_plaintext.decode())
