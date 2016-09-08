# -*- coding: utf8 -*-
import secp256k1
from secp256k1 import PrivateKey, PublicKey, ALL_FLAGS

from raiden.utils import sha3

GLOBAL_CTX = secp256k1.lib.secp256k1_context_create(secp256k1.ALL_FLAGS)


def recover_publickey(messagedata, signature):
    if len(signature) != 65:
        raise ValueError('invalid signature')

    key = PublicKey(
        ctx=secp256k1.lib.secp256k1_context_clone(GLOBAL_CTX),
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
        ctx=secp256k1.lib.secp256k1_context_clone(GLOBAL_CTX)
    )

    return publickey.serialize(compressed=False)


def sign(messagedata, private_key):
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise ValueError('invalid private_key')

    key = PrivateKey(
        private_key,
        ctx=secp256k1.lib.secp256k1_context_clone(GLOBAL_CTX),
        raw=True,
    )

    message_hash = sha3(messagedata)
    secp_signature = key.ecdsa_sign_recoverable(message_hash, raw=True)
    signature_data = key.ecdsa_recoverable_serialize(secp_signature)
    signature = signature_data[0] + chr(signature_data[1])

    if len(signature) != 65:
        raise ValueError('invalid signature')

    publickey = key.pubkey.serialize(compressed=False)

    return signature, publickey


def address_from_key(key):
    return sha3(key[1:])[-20:]
