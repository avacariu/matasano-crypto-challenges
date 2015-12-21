import lib.crypto

with open("challenge-data/8.txt", "r") as f:
    for i, line in enumerate(f):
        ciphertext = bytes.fromhex(line.strip())
        if lib.crypto.aes_is_ecb(ciphertext):
            print(i, line)
            break
