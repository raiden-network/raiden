# -*- coding: utf8 -*-
import secp256k1
from secp256k1 import PublicKey, ALL_FLAGS

from raiden.utils import sha3

# From the secp256k1 header file:
#
#     The purpose of context structures is to cache large precomputed data tables
#     that are expensive to construct, and also to maintain the randomization data
#     for blinding.
#
#     Do not create a new context object for each operation, as construction is
#     far slower than all other API calls (~100 times slower than an ECDSA
#     verification).
#
#     A constructed context can safely be used from multiple threads
#     simultaneously, but API call that take a non-const pointer to a context
#     need exclusive access to it. In particular this is the case for
#     secp256k1_context_destroy and secp256k1_context_randomize.
#
#     Regarding randomization, either do it once at creation time (in which case
#     you do not need any locking for the other calls), or use a read-write lock.
#
GLOBAL_CTX = secp256k1.lib.secp256k1_context_create(secp256k1.ALL_FLAGS)


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
