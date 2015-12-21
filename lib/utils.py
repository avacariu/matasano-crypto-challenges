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


