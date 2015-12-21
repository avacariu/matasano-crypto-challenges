from lib.crypto import aes_ecb_encrypt, aes_ecb_decrypt, pkcs7
import os
from collections import OrderedDict

key = os.urandom(16)

def kv_decode(data: str) -> dict:
    """
    Takes in k=v&k2=v4 sort of string and outputs the corresponding dict

    Assumes well-formed input
    """

    result = OrderedDict()

    for kv in data.split('&'):
        k, v = kv.split('=')
        result[k] = v

    return result


def profile_for(email: str) -> dict:
    clean_email = email.replace('&', '').replace('=', '')

    user_details = OrderedDict([
        ("email", clean_email),
        ("uid", 10),
        ("role", "user"),
    ])

    return "&".join(k + "=" + str(v) for k,v in user_details.items())


def encrypt_profile(profile: str) -> bytes:
    ct = aes_ecb_encrypt(key, pkcs7(profile.encode()))

    return (key, ct)


def decrypt_profile(key: bytes, profile_ciphertext: bytes) -> dict:
    profile_encoded = aes_ecb_decrypt(key, profile_ciphertext)
    return kv_decode(profile_encoded.decode())


# create a ciphertext block that is b'admin<PADDING>'
k, ct = encrypt_profile(profile_for('x'*10 + 'admin' + chr(11)*11))
admin_block = ct[16:32]

# push 'role=' to the end of the second block
k, ct = encrypt_profile(profile_for('x'*13))

chosen_ct = ct[:32] + admin_block

print(chosen_ct, decrypt_profile(k, chosen_ct))
