import pprint
import multiprocessing
import lib.xor

pool = multiprocessing.Pool(4)

strings = iter([])
with open("challenge-data/4.txt", "r") as f:
    strings = map(str.strip, f.readlines())

pprint.pprint(list(lib.xor.detect_single_byte(strings, map_fn=pool.map)))
