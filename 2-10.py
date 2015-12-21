import lib.crypto
import base64

key = b"YELLOW SUBMARINE"
with open("challenge-data/10.txt", 'rb') as f:
    print(lib.crypto.aes_cbc_decrypt(key, base64.b64decode(f.read())).decode())
