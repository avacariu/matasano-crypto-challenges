import lib.random
import random
import time

time.sleep(random.randint(40, 1000))
twister = lib.random.MersenneTwister(int(time.time()))
time.sleep(random.randint(40, 1000))
r = twister.extract_number()

print("Want to guess seed for: ", r)

# to crack, just brute force
seed_guess = int(time.time())
guess_twister = lib.random.MersenneTwister(seed_guess)
guess_result = guess_twister.extract_number()
while guess_result != r:
    seed_guess -= 1
    guess_twister._seed(seed_guess)
    guess_result = guess_twister.extract_number()

print(seed_guess, guess_result, r)
