import subprocess
import codecs

def primegen():
    args = ["openssl", "prime", "-generate", "-bits", "1024"]
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

p = primegen()
q = primegen()

n = p * q
et = (p-1) * (q-1)
e = 3
d = invmod(e, et)

# encrypt 42
c = pow(42, e, n)

assert 42 == pow(c, d, n)

# encrypt a string
da_str = "forty-two"
print("original:", da_str)

c = pow(str2int(da_str), e, n)

print("ciphertext:", c)
print("plaintext:", int2str(pow(c, d, n)))
