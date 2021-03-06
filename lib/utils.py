import itertools
import operator

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i+n]


def hamming_distance(t1: bytes, t2: bytes) -> int:
    def str2bin(text: bytes) -> str:
        bin_strings = []
        for char in text:
            bin_strings.extend(map(int, bin(char)[2:].zfill(8)))

        return bin_strings

    if len(t1) != len(t2):
        raise ValueError("Unequal length")
    return sum(itertools.starmap(operator.xor, zip(str2bin(t1), str2bin(t2))))


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x^y for x, y in zip(a, b))


def pairwise(iterable):
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)

# this function is based on the code in Applied Cryptography by Bruce Schneier
def modexp(number, power, mod):

    s = 1

    while power != 0:
        if power & 1:
            s = (s * number) % mod
        power >>= 1
        number = (number * number) % mod;

    return s

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
