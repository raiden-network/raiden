from ethereum.utils import big_endian_to_int, sha3, int_to_big_endian, privtoaddr
#from ethereum.keys import privtoaddr
from bitcoin import encode_pubkey, N, P
import sys
from Crypto.Hash import keccak as keccaklib

# hashing


def keccak_256(x):
    return keccaklib.new(digest_bits=256, data=x)


def keccak(seed):
    return keccak_256(seed).digest()


def ishash(h):
    return isinstance(h, bytes) and len(h) == 32


def isaddress(a):
    return isinstance(a, bytes) and len(a) == 20


def pex(h):
    return str(h).encode('hex')[:8]


def lpex(lst):
    return [pex(l) for l in lst]


def activate_ultratb():
    from IPython.core import ultratb
    sys.excepthook = ultratb.VerboseTB(call_pdb=True, tb_offset=6)
