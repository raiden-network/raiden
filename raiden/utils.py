from ethereum.utils import big_endian_to_int, sha3
#from ethereum.keys import privtoaddr
from bitcoin import encode_pubkey, N, P


def ishash(h):
    return isinstance(h, bytes) and len(h) == 32


def isaddress(a):
    return isinstance(a, bytes) and len(a) == 20


def pex(h):
    return str(h).encode('hex')[:8]
