# -*- coding: utf-8 -*-
from coincurve import PublicKey
from raiden.utils import sha3


def recover_publickey(messagedata, signature):
    if len(signature) != 65:
        raise ValueError('invalid signature')

    signature = signature[:-1] + chr(signature[-1] - 27).encode()
    publickey = PublicKey.from_signature_and_message(
        signature,
        messagedata,
        hasher=sha3,
    )
    return publickey.format(compressed=False)


def sign(messagedata, private_key):
    signature = private_key.sign_recoverable(messagedata, hasher=sha3)
    if len(signature) != 65:
        raise ValueError('invalid signature')

    return signature[:-1] + chr(signature[-1] + 27).encode()


def address_from_key(key):
    return sha3(key[1:])[-20:]
