import os
import sys
import random
import hashlib

import threading
import queue

from lib.crypto import aes_cbc_encrypt, aes_cbc_decrypt, pkcs7

p = int("""
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

def gen_key(s):
    s_bytes = s.to_bytes((s.bit_length() // 8) + 1, sys.byteorder)
    return hashlib.sha1(s_bytes).digest()[:16]


class Foo(threading.Thread):
    def __init__(self, network, type):
        super().__init__()
        self.network = network
        self.type = type
        self.msg_queue = queue.Queue()

    def run(self):
        if self.type == 'alice':
            self._run_alice()
        else:
            self._run_bob()

    def _run_alice(self):
        self.network.send('bob', (p, g))

        # we're receiving the 'negotiated' group here
        bob_ack, neg_p, neg_g = self.msg_queue.get()

        a = random.SystemRandom().randrange(0, neg_p)
        A = pow(neg_g, a, neg_p)

        self.network.send('bob', A)

        B = self.msg_queue.get(block=True)

        s = pow(B, a, neg_p)
        key = gen_key(s)

        print("alice's key\t\t", key)

        iv = os.urandom(16)
        message = b"Hi, bob!"
        ct = aes_cbc_encrypt(key, pkcs7(message), iv)

        self.network.send('bob', (ct, iv))

        ct_from_bob, bob_iv = self.msg_queue.get()
        pt_from_bob = aes_cbc_decrypt(key, ct_from_bob, bob_iv)

        print("Alice got the following message from Bob:")
        print(pt_from_bob)

        self.network.send(None, 'disconnect alice')

    def _run_bob(self):
        p, g = self.msg_queue.get()

        self.network.send('alice', ('ack', p, g))

        A = self.msg_queue.get()

        b = random.SystemRandom().randrange(0, p)
        B = pow(g, b, p)

        self.network.send('alice', B)

        s = pow(A, b, p)
        key = gen_key(s)

        print("bob's key\t\t", key)

        ct_from_alice, alice_iv = self.msg_queue.get()
        pt_from_alice = aes_cbc_decrypt(key, ct_from_alice, alice_iv)

        print("Bob got the following message from Alice:")
        print(pt_from_alice)

        iv = os.urandom(16)
        ct = aes_cbc_encrypt(key, pt_from_alice, iv)

        self.network.send('alice', (ct, iv))

        self.network.send(None, 'disconnect bob')


class Network:
    def __init__(self, malicious=False, attack_g=g):
        self.eve = malicious
        self.attack_g = attack_g

        self.alice = Foo(self, 'alice')
        self.bob = Foo(self, 'bob')

        self.messages = queue.Queue()

    def send(self, dst, msg):
        self.messages.put((dst, msg))

    def run(self):

        self.alice.start()
        self.bob.start()
        alice_running = True
        bob_running = True

        while alice_running or bob_running:
            dest, msg = self.messages.get()
            if dest is None:
                if msg == 'disconnect bob':
                    bob_running = False
                    continue
                elif msg == 'disconnect alice':
                    alice_running = False
                    continue
                else:
                    print("Got invalid message to None (ignoring):", msg)
                    continue

            if dest == 'alice':

                if self.eve:
                    if isinstance(msg, tuple) and 'ack' in msg:
                        ack, _p, _g = msg
                        msg = ack, _p, self.attack_g
                    else:
                        # check if Bob is sending ciphertext
                        try:
                            ct, iv = msg
                        except (ValueError, TypeError):
                            pass
                        else:
                            # try to decrypt for funsies
                            if self.attack_g != g:
                                # (p-1)**a % p == 1 or p-1 depending on whether
                                # a is even or odd, so try both
                                session_keys = {1: [1], p: [0], (p-1): [1, p-1]}
                                s = session_keys[self.attack_g]

                                for sk in s:
                                    key = gen_key(sk)
                                    pt = aes_cbc_decrypt(key, ct, iv)
                                    print("MITM from bob\t\t", pt)

                self.alice.msg_queue.put(msg)

            elif dest == 'bob':

                if self.eve:
                    # check if Alice is sending (p, g) to Bob
                    try:
                        _p, _g = msg
                        _p = int(_p)
                        _g = int(_g)
                    except (ValueError, TypeError):
                        pass
                    else:
                        msg = (_p, self.attack_g)

                    # check if Alice is sending ciphertext
                    try:
                        ct, iv = msg
                        assert isinstance(ct, bytes)
                    except (ValueError, TypeError, AssertionError):
                        pass
                    else:
                        # try to decrypt for funsies
                        if self.attack_g != g:
                            # (p-1)**a % p == 1 or p-1 depending on whether
                            # a is even or odd, so try both
                            session_keys = {1: [1], p: [0], (p-1): [1, p-1]}
                            s = session_keys[self.attack_g]

                            for sk in s:
                                key = gen_key(sk)
                                pt = aes_cbc_decrypt(key, ct, iv)
                                print("MITM from alice\t\t", pt)

                self.bob.msg_queue.put(msg)
            else:
                print("Got invalid destination (ignoring):", dest)


        self.alice.join()
        self.bob.join()

network = Network(malicious=True, attack_g=(p-1))
network.run()
