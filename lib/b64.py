import string

alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
padding_char = "="

def encode(src: 'hex string') -> str:
    src_bytes = bytes.fromhex(src)

    padding = 0
    if (len(src_bytes) % 3):
        padding = 3 - (len(src_bytes) % 3)

    encoded = []

    for b1, b2, b3 in zip(*[iter(src_bytes + b'\00'*padding)]*3):
        out1 = alphabet[b1 >> 2]
        out2 = alphabet[(b1 & 3) << 4 | b2 >> 4]
        out3 = alphabet[(b2 & 15) << 2 | b3 >> 6]
        out4 = alphabet[b3 & 63]

        encoded.extend([out1, out2, out3, out4])

    # since we padded src_bytes with zeros, we need to replace the padded stuff
    # with '=' in output
    for i in range(padding):
        encoded[-i] = padding_char

    return ''.join(encoded)
