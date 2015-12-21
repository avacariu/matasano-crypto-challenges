from lib.crypto import aes_ecb_encrypt, detect_ecb_cbc, pkcs7
import base64
import os

key = os.urandom(16)


def encryption_oracle(plaintext):
    suffix = ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
              "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
              "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
              "YnkK")
    pt = plaintext + base64.b64decode(suffix)
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

hidden_text_length = len(encryption_oracle(b''))
guess_plaintext = bytearray(b'A' * hidden_text_length)

htl = hidden_text_length

# ciphertext with the first byte of the output encoded as the last byte
for i in range(1, hidden_text_length+1):
    target_ct = encryption_oracle(bytes(b'A' * (htl - i)))

    for b in range(256):
        possible_byte = b.to_bytes(length=1, byteorder="big")
        guess = bytes(guess_plaintext[1:] + possible_byte)

        assert len(guess) == hidden_text_length

        ct = encryption_oracle(guess)

        # check the entire thing, not just the last byte
        # if you check just ct[htl-1] then you get false positives
        # TODO figure out why
        if ct[:htl-1] == target_ct[:htl-1]:
            guess_plaintext.append(b)
            guess_plaintext.pop(0)
            break

    else:
        print("Didn't find the last byte\n")
        break

print(guess_plaintext.decode())
