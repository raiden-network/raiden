# -*- coding: utf8 -*-
from c_secp256k1 import ecdsa_recover_compact as c_ecdsa_recover_compact
from c_secp256k1 import ecdsa_sign_compact as c_ecdsa_sign_compact

from raiden.utils import sha3


def recover_publickey(messagedata, signature):
    if len(signature) != 65:
        raise ValueError('invalid signature')

    message_hash = sha3(messagedata)
    publickey = c_ecdsa_recover_compact(message_hash, signature)

    return publickey


def sign(data, private_key):
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise ValueError('invalid private_key')

    message_hash = sha3(data)
    signature = c_ecdsa_sign_compact(message_hash, private_key)

    if len(signature) != 65:
        raise ValueError('invalid signature')

    publickey = c_ecdsa_recover_compact(message_hash, signature)

    return signature, publickey


def address_from_key(key):
    return sha3(key[1:])[-20:]
