import hashlib
import codecs
import time
import string
import itertools
import requests
from flask import Flask, request, Response
from lib.utils import xor

app = Flask(__name__)

key = b'YELLOW SUBMARINE'

def hmac(key, message, hexify=False):
    blocksize = 64
    hash = lambda m: hashlib.sha1(m).digest()

    if len(key) > blocksize:
        key = hashlib.sha1(key).digest()

    if len(key) < blocksize:
        key = key.ljust(blocksize, b'\00')

    o_key_pad = xor(b'\x5c' * blocksize, key)
    i_key_pad = xor(b'\x36' * blocksize, key)

    digest = hash(o_key_pad + hash(i_key_pad + message))

    if hexify:
        return codecs.encode(digest, 'hex')

    return digest

def insecure_compare(test, sig):
    test_sig = hmac(key, test, hexify=True)

    if len(sig) != len(test_sig):
        return False

    for a, b in zip(test_sig, sig):
        if a != b:
            return False
        time.sleep(0.005)

    return True

@app.route('/test')
def test():
    file = request.args['file'].encode()
    sig = request.args['signature'].encode()

    if insecure_compare(file, sig):
        return Response(status=200)
    else:
        return Response(status=500)


# import this module and then use this function
# or just copy and %paste in ipython
def determine_mac(text, server='http://localhost:5000'):
    """Attacks the given server to figure out the mac for the given text"""

    rest_path = server + '/test?file={string}&signature={sig}'

    from concurrent.futures import ThreadPoolExecutor

    signature = ''

    def guess(sig_c):
        signature, c = sig_c
        guess_sig = (signature + c).ljust(40, 'x')

        total_time = 0
        iterations = 250

        for i in range(iterations):
            rv = requests.get(rest_path.format(string=text, sig=guess_sig))
            total_time += rv.elapsed.total_seconds()

        return c, total_time

    with ThreadPoolExecutor(max_workers=len(string.hexdigits[:16])) as ex:
        for pos in range(40):
            res = ex.map(guess, itertools.zip_longest([signature], string.hexdigits[:16],
                                                     fillvalue=signature))

            times = sorted(res, key=lambda x: x[1])
            signature += times.pop()[0]

    return signature

if __name__ == "__main__":
    app.run(debug=True, threaded=True)
