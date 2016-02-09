import os
import sys
import random
import hashlib

import threading
import queue
from collections import namedtuple

from lib.crypto import aes_cbc_encrypt, aes_cbc_decrypt, pkcs7
from lib.utils import xor

N = int("""
       ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
       e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
       3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
       6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
       24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
       c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
       bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
       fffffffffffff
       """.replace('\n', '').replace(' ', ''), 16)

g = 2
k = 3

def hmac(key, message, hexify=False):
    blocksize = 64
    hash = lambda m: hashlib.sha256(m).digest()

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

Msg = namedtuple('Msg', ['type', 'body'])

class Server(threading.Thread):
    def __init__(self, network):
        super().__init__()
        self.network = network
        self.messages = queue.Queue()

    def run(self):
        # stuff to save
        email = None
        password = None
        salt = None
        v = None
        u = None

        b = random.SystemRandom().randrange(0, N)

        while True:
            msg = self.messages.get()

            if msg.type == 'neg':
                print('got neg')
                email, password = msg.body
                self.network.send('client', Msg('negack', (N, g, k)))

                salt = random.SystemRandom().randrange(0, N)
                xH = hashlib.sha256(salt.to_bytes(256, 'big') + password.encode())
                x = int.from_bytes(xH.digest(), 'big')

                v = pow(g, x, N)

            elif msg.type == 'IA':
                print('got ia')
                I, A = msg.body

                B = k*v + pow(g, b, N)
                self.network.send('client', Msg('saltB', (salt, B)))

                uH = hashlib.sha256(A.to_bytes(256, 'big') + B.to_bytes(256, 'big'))
                u = int.from_bytes(uH.digest(), 'big')

            elif msg.type == 'validate':
                print('got validate')
                received_hmac = msg.body

                S = pow((A * pow(v, u, N)), b, N)
                K = hashlib.sha256(S.to_bytes(256, 'big')).digest()

                if received_hmac == hmac(K, salt.to_bytes(256, 'big')):
                    self.network.send('client', Msg('validated', 'ok'))

                    self.network.send(None, Msg('disconnect', 'server'))
                    return

class Client(threading.Thread):
    def __init__(self, network):
        super().__init__()

        self.network = network
        self.messages = queue.Queue()

    def run(self):
        email = 'test@example.com'
        password = 'hunter2'

        self.network.send('server', Msg('neg', (email, password)))

        N, g, k = self.messages.get().body
        a = random.SystemRandom().randrange(0, N)
        A = pow(g, a, N)

        self.network.send('server', Msg('IA', (email, A)))

        salt, B = self.messages.get().body

        uH = hashlib.sha256(A.to_bytes(256, 'big') + B.to_bytes(256, 'big'))
        u = int.from_bytes(uH.digest(), 'big')

        xH = hashlib.sha256(salt.to_bytes(256, 'big') + password.encode())
        x = int.from_bytes(xH.digest(), 'big')

        S = pow((B - k * pow(g, x, N)), (a + u*x), N)
        K = hashlib.sha256(S.to_bytes(256, 'big')).digest()

        self.network.send('server', Msg('validate', hmac(K, salt.to_bytes(256, 'big'))))

        print("validated", self.messages.get())

        self.network.send(None, Msg('disconnect', 'client'))

class Network:
    def __init__(self, malicious=False):
        self.eve = malicious

        self.server = Server(self)
        self.client = Client(self)

        self.messages = queue.Queue()

    def send(self, dst, msg):
        self.messages.put((dst, msg))

    def run(self):

        self.server.start()
        self.client.start()
        server_running = True
        client_running = True

        while server_running or client_running:
            dest, msg = self.messages.get()
            if dest is None:
                if msg.type == 'disconnect':
                    if msg.body == 'server':
                        server_running = False
                        continue
                    elif msg.body == 'client':
                        client_running = False
                        continue
                    else:
                        print('got invalid disconnect')
                        continue
                else:
                    print('got invalid None message')

            if dest == 'client':
                self.client.messages.put(msg)
            elif dest == 'server':
                self.server.messages.put(msg)
            else:
                print("Got invalid destination (ignoring):", dest)


        self.server.join()
        self.client.join()

network = Network()
network.run()
