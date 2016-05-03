import subprocess
import codecs
import random
import hashlib

def primegen(size="1024"):
    args = ["openssl", "prime", "-generate", "-bits", size]
    return int(subprocess.check_output(args).decode())

def extended_gcd(a, b):
    s, t, r             = 0, 1, b
    old_s, old_t, old_r = 1, 0, a

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient*r
        old_s, s = s, old_s - quotient*s
        old_t, t = t, old_t - quotient*t

    return (old_r, (old_s, old_t))

def invmod(a, m):
    g, (x, y) = extended_gcd(a, m)

    if g != 1:
        raise Exception("Modular inverse does not exist")

    return x % m

def str2int(string):
    return int(codecs.encode(string.encode(), "hex"), 16)

def int2str(integer):
    return codecs.decode(hex(integer)[2:], "hex").decode()

def oracle(msg: bytes, sig: int):
    """
    Checks whether the signature is valid for the message.
    """

    decrypted_sig = pow(sig, e, n)
    decrypted_sig_bytes = decrypted_sig.to_bytes(n.bit_length() // 8, 'big')

    # to simplify this, instead of reading all the 00 01 ff ff ... ff 00, just
    # look for the second occurrance of the 00, assume the next byte is the the
    # ASN.1 info, ignore that since we know that we'll just read the next 16
    # bytes since we know MD5 was used
    md5_start = decrypted_sig_bytes.find(b'\x00', 2) + 2
    hash_bytes = decrypted_sig_bytes[md5_start:md5_start+16]
    print(hash_bytes)

    return hashlib.md5(msg).digest() == hash_bytes

def nthroot(x, n):
    u, s = x, x+1

    while u < s:
        s = u
        t = (n - 1)*s + x // pow(s, n-1)
        u = t // n

    return s

p = primegen('512')
q = primegen('512')

# key is going to be 1024 bits
n = p * q
et = (p-1) * (q-1)
e = 3
d = invmod(e, et)

msg = b"hi mom"
msg_hash = hashlib.md5(msg).digest()

# pretend the \x10 is the ASN.1 stuff
sig = b'\x00\x01\xff\x00' + b'\x10' + msg_hash
sig += b'\x00' * (n.bit_length() // 8 - len(sig))

print(oracle(msg, nthroot(int.from_bytes(sig, 'big'), 3)+1))
