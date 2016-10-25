# -*- coding: utf-8 -*-
from secp256k1 import PublicKey, ALL_FLAGS

from raiden.utils import sha3, GLOBAL_CTX


def recover_publickey(messagedata, signature):
    if len(signature) != 65:
        raise ValueError('invalid signature')

    key = PublicKey(
        ctx=GLOBAL_CTX,
        flags=ALL_FLAGS,  # FLAG_SIGN is required to recover publickeys
    )

    signature_data = key.ecdsa_recoverable_deserialize(
        signature[:64],
        ord(signature[64]),
    )

    message_hash = sha3(messagedata)
    publickey_data = key.ecdsa_recover(message_hash, signature_data, raw=True)

    publickey = PublicKey(
        publickey_data,
        ctx=GLOBAL_CTX
    )

    return publickey.serialize(compressed=False)


def sign(messagedata, private_key):
    message_hash = sha3(messagedata)
    secp_signature = private_key.ecdsa_sign_recoverable(message_hash, raw=True)
    signature_data = private_key.ecdsa_recoverable_serialize(secp_signature)
    signature = signature_data[0] + chr(signature_data[1])

    if len(signature) != 65:
        raise ValueError('invalid signature')

    return signature


def address_from_key(key):
    return sha3(key[1:])[-20:]
