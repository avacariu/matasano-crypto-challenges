from lib.random import MersenneTwister

twister = MersenneTwister(1244)
outputs = [twister.extract_number() for i in range(twister.n)]


def test(y, expect, twister):
    y ^= (y >> twister.u) & twister.d
    y ^= (y << twister.s) & twister.b
    y ^= (y << twister.t) & twister.c
    y ^= (y >> twister.l)

    print(y, expect)
    assert y == expect


def get_bit(val, bit):
    """Retrieve the bit from val counting from the right"""
    if bit < 0:
        return 0
    return (val >> bit) & 1

# For the following two functions, refer to this diagram to understand why I'm
# doing it like this:
# https://upload.wikimedia.org/wikipedia/commons/b/b5/Mersenne_Twister_visualisation.svg


def undo_rightshift(val, shift):
    # Since the original was shifted right, we already have the first part, but
    # to be consistent we'll xor it with 0 anyways, and then go through the bits
    # consecutively because we can use a previous bit to solve a current one
    # (again, we can only do this since we shifted right)
    y = 0
    # go from 31 -> 0 because that's the order we have data available in
    for i in range(31, -1, -1):
        y |= (get_bit(val, i) ^ get_bit(y, (i + shift))) << i

    return y


def undo_leftshift(val, shift, mask):
    # Since we're shifting left and ANDing before XORing, to reverse the
    # operation we have to start at right part, as that's where the only data we
    # have available exists (i.e. we have the result and the mask, so if we xor
    # those together, we get the last bits of the original value, and we can
    # later use that information when we get there in our for loop)
    y = 0
    for i in range(32):
        y |= (get_bit(val, i) ^ (get_bit(y, i - shift) & get_bit(mask, i))) << i

    return y


def untemper(z, twister):
    y = undo_rightshift(z, twister.l)
    y = undo_leftshift(y, twister.t, twister.c)
    y = undo_leftshift(y, twister.s, twister.b)
    y = undo_rightshift(y, twister.u)

    test(y & 0xFFFFFFFF, z, twister)

    return y

# generate a few more values to test whether our spliced generator works
# properly
expect_test_outputs = [twister.extract_number() for i in range(twister.n)]

twister.MT = [untemper(z, twister) for z in outputs]

test_outputs = [twister.extract_number() for i in range(twister.n)]

for expect, output in zip(expect_test_outputs, test_outputs):
    assert expect == output
