import lib.crypto

src = b"YELLOW SUBMARINE"
expect = b"YELLOW SUBMARINE\x04\x04\x04\x04"

assert lib.crypto.pkcs7(src, 20) == expect
