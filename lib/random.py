def _lower_bits(num_bits, data):
    return ((1 << num_bits) - 1) & data


# this is a straight implementation of the Mersenne Twister pseudocode on
# Wikipedia: https://en.wikipedia.org/wiki/Mersenne_Twister
class MersenneTwister:
    w, n, m, r = 32, 624, 397, 31
    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18
    f = 1812433253

    def __init__(self, seed):
        self.seed = seed
        self.MT = [0] * self.n
        self.index = self.n + 1
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = _lower_bits(self.w, ~self.lower_mask)

        self._seed(seed)

    def _seed(self, seed):
        self.index = self.n
        self.MT[0] = seed
        for i in range(1, self.n):
            computed = self.f * (self.MT[i-1] ^ (self.MT[i-1] >> (self.w-2))) + 1
            self.MT[i] = _lower_bits(self.w, computed)

    def extract_number(self):
        if self.index > self.n:
            raise Exception("Generator was never seeded")
        elif self.index == self.n:
            self.twist()

        y = self.MT[self.index]
        y ^= (y >> self.u) & self.d
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= (y >> self.l)

        self.index += 1
        return _lower_bits(self.w, y)

    def twist(self):
        for i in range(self.n):
            upper_portion = self.MT[i] & self.upper_mask
            lower_portion = self.MT[(i + 1) % self.n] & self.lower_mask
            x = upper_portion + lower_portion

            xA = x >> 1

            if x % 2:
                xA ^= self.a

            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA

        self.index = 0
