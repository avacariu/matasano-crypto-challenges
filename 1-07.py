import lib.crypto
import base64

key = b"YELLOW SUBMARINE"

with open("challenge-data/7.txt", "rb") as f:
    ciphertext = base64.b64decode(f.read())

plaintext = lib.crypto.aes_ecb_decrypt(key, ciphertext)

print(plaintext.decode())
