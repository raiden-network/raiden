# -*- coding: utf-8 -*-
import os
import re
import sys
import string
import random

from coincurve import PrivateKey
from Crypto.Hash import keccak as keccaklib
from ethereum.utils import sha3
from ethereum.utils import remove_0x_head

import raiden

__all__ = (
    'sha3',
    'keccak_256',
    'keccak',
    'ishash',
    'isaddress',
    'make_address',
    'make_privkey_address',
    'publickey_to_address',
    'privatekey_to_address',
    'pex',
    'lpex',
    'get_contract_path',
    'safe_lstrip_hex',
    'camel_to_snake_case'
)

LETTERS = string.printable

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


def safe_address_decode(address):
    try:
        address = safe_lstrip_hex(address)
        address = address.decode('hex')
    except TypeError:
        pass

    return address


def keccak_256(data):
    return keccaklib.new(digest_bits=256, data=data)


def keccak(seed):
    return keccak_256(seed).digest()


def ishash(data):
    return isinstance(data, (bytes, bytearray)) and len(data) == 32


def isaddress(data):
    return isinstance(data, (bytes, bytearray)) and len(data) == 20


def make_address():
    return bytes(''.join(random.choice(LETTERS) for _ in range(20)))


def make_privkey_address():
    private_key_bin = sha3(''.join(random.choice(LETTERS) for _ in range(20)))
    privkey = PrivateKey(private_key_bin)
    pubkey = privkey.public_key.format(compressed=False)
    address = publickey_to_address(pubkey)
    return privkey, address


def pex(data):
    return str(data).encode('hex')[:8]


def lpex(lst):
    return [pex(l) for l in lst]


def activate_ultratb():
    from IPython.core import ultratb
    sys.excepthook = ultratb.VerboseTB(call_pdb=True, tb_offset=6)


def host_port_to_endpoint(host, port):
    return "{}:{}".format(host, port)


def split_endpoint(endpoint):
    host, port = endpoint.split(':')[:2]
    port = int(port)
    return (host, port)


def publickey_to_address(publickey):
    return sha3(publickey[1:])[12:]


def privatekey_to_address(private_key_bin):
    private_key = PrivateKey(private_key_bin)
    pubkey = private_key.public_key.format(compressed=False)
    return publickey_to_address(pubkey)


def get_project_root():
    return os.path.dirname(raiden.__file__)


def get_contract_path(contract_name):
    contract_path = os.path.join(
        get_project_root(),
        'smart_contracts',
        contract_name
    )
    return os.path.realpath(contract_path)


def safe_lstrip_hex(val):
    if isinstance(val, basestring):
        return remove_0x_head(val)
    return val


def get_encoded_transfers(their_transfer, our_transfer):
    """Check for input sanity and return the encoded version of the transfers"""
    if not their_transfer and our_transfer:
        raise ValueError(
            "There is no reason to provide our_transfer when their_transfer"
            " is not provided"
        )
    their_encoded = their_transfer.encode() if their_transfer else ""
    our_encoded = our_transfer.encode() if our_transfer else ""
    return their_encoded, our_encoded


def camel_to_snake_case(name):
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def snake_to_camel_case(snake_string):
    return snake_string.title().replace("_", "")


def channel_to_api_dict(channel):
    """Takes in a Channel Object and turns it into a dictionary for
    usage in the REST API. Decoding from binary to hex happens through
    the marshmallow AddressField in encoding.py.
    """
    return {
        "channel_address": channel.channel_address,
        "token_address": channel.token_address,
        "partner_address": channel.partner_address,
        "settle_timeout": channel.settle_timeout,
        "balance": channel.contract_balance,
        "state": channel.state
    }
