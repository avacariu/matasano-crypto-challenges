from lib.crypto import aes_ctr
import base64

ciphertext = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
ciphertext = base64.b64decode(ciphertext)

expect = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

assert aes_ctr(b"YELLOW SUBMARINE", ciphertext) == expect
