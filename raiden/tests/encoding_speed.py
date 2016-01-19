import pytest
from timeit import timeit

setup = """
import cPickle
import umsgpack
from raiden.messages import Ping, decode, MediatedTransfer, Lock, Ack
from raiden.utils import privtoaddr, sha3

privkey = 'x' * 32
address = privtoaddr(privkey)

m0 = Ping(nonce=0)
m0.sign(privkey)

m1 = MediatedTransfer(10, address, 100, address, address,
        Lock(100, 50, sha3(address)), address, address)
m1.sign(privkey)

m2 = Ack(address, sha3(privkey))
"""

exec(setup)

codecs = {
    'rlp':     'd = {}.encode(); decode(d)',
    'cPickle': 'd = cPickle.dumps({}, 2); cPickle.loads(d)',
    'msgpack': 'd = umsgpack.packb({}.serialize()); umsgpack.unpackb(d)'
}

for m in ('m0', 'm1', 'm2'):
    msg_name = locals()[m]
    print("\n{}".format(msg_name))
    for codec_name, code_base in codecs.items():
        code = code_base.format(m)

        exec(code)
        print('{} encoded {} size: {}'.format(codec_name, msg_name, len(d)))

        result = timeit(code, setup, number=10000)
        print '{} {} (en)(de)coding speed: {}'.format(codec_name, msg_name, result)
