# -*- coding: utf8 -*-
from ethereum.slogging import getLogger
from secp256k1 import PrivateKey, PublicKey, ALL_FLAGS

from raiden.utils import sha3

log = getLogger(__name__)  # pylint: disable=invalid-name


def recover_publickey(messagedata, signature):
    if len(signature) != 65:
        raise ValueError('invalid signature')

    key = PublicKey(flags=ALL_FLAGS)  # FLAG_SIGN is required to recover publickeys
    signature_data = key.ecdsa_recoverable_deserialize(
        signature[:64],
        ord(signature[64]),
    )

    message_hash = sha3(messagedata)
    publickey_data = key.ecdsa_recover(message_hash, signature_data, raw=True)
    publickey = PublicKey(publickey_data).serialize(compressed=False)

    return publickey


def sign(messagedata, private_key):
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise ValueError('invalid private_key')

    key = PrivateKey(private_key, raw=True)

    message_hash = sha3(messagedata)
    secp_signature = key.ecdsa_sign_recoverable(message_hash, raw=True)
    signature_data = key.ecdsa_recoverable_serialize(secp_signature)
    signature = signature_data[0] + chr(signature_data[1])

    if len(signature) != 65:
        raise ValueError('invalid signature')

    publickey = key.pubkey.serialize(compressed=False)

    return signature, publickey
