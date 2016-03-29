import subprocess
import codecs
import decimal

def primegen():
    args = ["openssl", "prime", "-generate", "-bits", "32"]
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

def encrypt(pt: str):
    """Generate public/private keypair, and return (pubkey, ciphertext)"""

    pt = str2int(pt)

    p = primegen()
    q = primegen()

    n = p * q
    et = (p-1) * (q-1)
    e = 3
    d = invmod(e, et)

    # encrypt 42
    return ((e,n), pow(pt, e, n))

# NOTE: This doesn't work if the plaintext is too large (i.e. > n)
plaintext = "42"
(_, n0), c0 = encrypt(plaintext)
(_, n1), c1 = encrypt(plaintext)
(_, n2), c2 = encrypt(plaintext)

m_s_0 = n1 * n2
m_s_1 = n0 * n2
m_s_2 = n0 * n1

N_012 = n0*n1*n2

result = (c0 * m_s_0 * invmod(m_s_0, n0) +
          c1 * m_s_1 * invmod(m_s_1, n1) +
          c2 * m_s_2 * invmod(m_s_2, n2)) % N_012

def nthroot(x, n):
    u, s = x, x+1

    while u < s:
        s = u
        t = (n - 1)*s + x / pow(s, n-1)
        u = t / n

    return int(s)

assert str2int(plaintext) == nthroot(result, 3)
