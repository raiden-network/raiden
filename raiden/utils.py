# -*- coding: utf8 -*-
import sys

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
    'pex',
    'lpex',
)

# hashing


def keccak_256(data):
    return keccaklib.new(digest_bits=256, data=data)


def keccak(seed):
    return keccak_256(seed).digest()


def ishash(data):
    return isinstance(data, (bytes, bytearray)) and len(data) == 32


def isaddress(data):
    return isinstance(data, (bytes, bytearray)) and len(data) == 20


def pex(data):
    return str(data).encode('hex')[:8]


def lpex(lst):
    return [pex(l) for l in lst]


def activate_ultratb():
    from IPython.core import ultratb
    sys.excepthook = ultratb.VerboseTB(call_pdb=True, tb_offset=6)
