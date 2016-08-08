# -*- coding: utf8 -*-
import sys
import string
import random

from Crypto.Hash import keccak as keccaklib
from ethereum.utils import big_endian_to_int, sha3, int_to_big_endian, privtoaddr

__all__ = (
    'sha3',
    'keccak_256',
    'big_endian_to_int',
    'int_to_big_endian',
    'privtoaddr',
    'keccak',
    'ishash',
    'isaddress',
    'make_address',
    'make_privkey_address',
    'pex',
    'lpex',
)

# hashing
LETTERS = string.printable


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
    privkey = sha3(''.join(random.choice(LETTERS) for _ in range(20)))
    return privkey, privtoaddr(privkey)


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
