#!/usr/bin/env python3
import operator
import binascii
import string
import math

from nltk.corpus import wordnet
import nltk.probability

def xor_equal_length(data: "hex string", key: "hex string") -> "hex string":
    data_bytes = bytes.fromhex(data)
    key_bytes = bytes.fromhex(key)

    xor_bytes = bytes(starmap(operator.xor, zip(data_bytes, key_bytes)))

    return binascii.hexlify(xor_bytes).decode('utf-8')


def crack_single_byte(data: "hex string") -> str:
    # TODO sort the list of possible decrypted texts because there might be
    # stuff that's not in wordnet, but is still valid

    data_bytes = bytes.fromhex(data)

    english_freq = nltk.probability.FreqDist(''.join(wordnet.words()))

    closeness = float("inf")
    possible_decrypted = None
    key = None
    for i in range(256):
        curr_possible_decrypted = None
        try:
            curr_possible_decrypted = ''.join(chr(i^x) for x in data_bytes)
            decrypted_freq = nltk.probability.FreqDist(curr_possible_decrypted.strip().replace(' ', '').lower())
        except:
            # doesn't matter what goes wrong. If something does go wrong, this
            # isn't a valid key.
            continue
        else:
            curr_closeness = len(decrypted_freq - english_freq)
            if curr_closeness <= closeness:
                possible_decrypted = curr_possible_decrypted
                closeness = curr_closeness
                key = i

    return key, possible_decrypted


def detect_single_byte(strings, map_fn=map) -> str:
    crack_attempt = map_fn(crack_single_byte, strings)

    def contains_only_english(s):
        if s is None:
            return False

        return not (set(s) - set(string.printable))

    return filter(contains_only_english, crack_attempt)


def repeating_key_bytes(text: bytes, key: bytes) -> "hex string":
    stretched_key = key * math.ceil(len(text) / len(key))
    return bytes([x^y for x, y in zip(text, stretched_key)])


def repeating_key(text: str, key: str) -> "hex string":
    xored = repeating_key_bytes(text.encode(), key.encode())
    return binascii.hexlify(xored).decode()
