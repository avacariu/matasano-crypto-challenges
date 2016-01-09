from lib.sha1 import sha1
import os

key = os.urandom(16)

def authenticate(message):
    return sha1(key + message)

def verify(message, mac):
    return sha1(key + message) == mac

mac = authenticate(b"test")
assert verify(b"test", mac) == True
assert verify(b"tes", mac) == False
