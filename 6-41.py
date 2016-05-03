import subprocess
import codecs
import random

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

plaintext = "forty-two"
int_p = str2int(plaintext)

# pretend we captured this in transit from client to server
captured_ciphertext = pow(int_p, e, n)

S = random.randint(2, n)

attack_cipher = pow(S, e, n) * captured_ciphertext % n

# pretend we're sending this to the server and it decrypts it for us
attack_plain = pow(attack_cipher, d, n)

original_plain = attack_plain * invmod(S, n) % n

print("original:", int2str(int_p))
print("plaintext:", int2str(original_plain))
