import os
import math
import random
import string
import itertools
import operator
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import openssl

from .utils import xor, chunks, pairwise

def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=openssl.backend)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    assert len(key) % 16 == 0
    assert len(plaintext) % 16 == 0
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=openssl.backend)
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_is_ecb(ciphertext: bytes, key_length=16) -> bool:

    num_blocks = len(ciphertext) / key_length
    if len(set(chunks(ciphertext, key_length))) < num_blocks:
        return True

    return False


def pkcs7(data: bytes, length=16) -> bytes:
    pad_len = (math.ceil(len(data) / length) * length) - len(data)

    if pad_len == 0:
        pad_len = length

    return data + bytes([pad_len]*pad_len)


def aes_cbc_encrypt(key: bytes, plaintext: bytes, iv=b'\x00'*16) -> bytes:

    padded_plaintext = pkcs7(plaintext)

    ciphertext = [iv]

    for chunk in chunks(padded_plaintext, 16):
        ct = aes_ecb_encrypt(key, xor(ciphertext[-1], chunk))
        ciphertext.append(ct)

    return b"".join(ciphertext[1:])


def aes_cbc_decrypt(key: bytes, ciphertext: bytes, iv=b'\x00'*16) -> bytes:
    assert len(ciphertext) % 16 == 0

    ciphertext_blocks = [iv] + list(chunks(ciphertext, 16))

    plaintext = []

    for i, chunk in enumerate(chunks(ciphertext, 16)):
        pt = aes_ecb_decrypt(key, chunk)
        plaintext.append(xor(pt, ciphertext_blocks[i]))

    return b"".join(plaintext)


def aes_ctr(key: bytes, text: bytes, nonce=0) -> bytes:
    ctr = nonce
    result = []
    for block in chunks(text, 16):
        ctr_bytes = bytes(8) + ctr.to_bytes(length=8, byteorder='little')
        keystream = aes_ecb_encrypt(key, ctr_bytes)
        result.append(xor(keystream, block))

        ctr += 1

    return b"".join(result)


def random_key(length=16) -> bytes:
    return os.urandom(length)


def encryption_oracle(plaintext: bytes, method='random') -> bytes:
    front_padding = bytes(random.sample(range(0,256), random.randint(5, 10)))
    back_padding = bytes(random.sample(range(0,256), random.randint(5, 10)))

    if method == 'random':
        method = random.choice(['ecb', 'cbc'])

    padded = pkcs7(front_padding + plaintext + back_padding)

    if method == 'ecb':
        return aes_ecb_encrypt(random_key(), padded)
    else:
        return aes_cbc_encrypt(random_key(), padded, iv=os.urandom(16))


def detect_ecb_cbc(oracle, blocksize=16) -> str:
    # idea: find a repeating 16 byte block
    #       if found, return ECB
    # we want a massive plaintext since the random padding in the oracle can
    # shift our blocks and it could be the case that there aren't two blocks
    # that are identical
    ct = oracle(b'0'*(blocksize*4))

    # ignore the first 16 bytes since they might be affected by random padding
    # the next 2 16 byte blocks are encrypted with the same key so should be
    # identical

    block1 = ct[blocksize : blocksize*2]
    block2 = ct[blocksize*2 : blocksize*3]

    if block1 == block2:
        return 'ecb'
    else:
        return 'cbc'


def validate_pkcs7_padding(padded: bytes) -> bytes:
    last_byte = padded[-1]
    padding = padded[-last_byte:]
    if len(set(padding)) == 1:
        return True, padded[:-last_byte]
    else:
        raise Exception("Invalid padding")
