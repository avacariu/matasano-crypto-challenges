from lib.crypto import RSA

rsa = RSA()
ct = rsa.encrypt("forty-two")
assert "forty-two" == rsa.decrypt(ct)
