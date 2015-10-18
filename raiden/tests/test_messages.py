from raiden.encoding import SignatureMissingError
from raiden.messages import Ping, Ack, decode, Lock, MediatedTransfer
from raiden.utils import privtoaddr, isaddress, pex, sha3
import pytest
import rlp

privkey = 'x' * 32
address = privtoaddr(privkey)


def test_signature():
    p = Ping(nonce=0)
    with pytest.raises(SignatureMissingError):
        p.sender
    p.sign(privkey)
    assert p.sender == address


def test_encoding():
    p = Ping(nonce=0)
    with pytest.raises(SignatureMissingError):
        p.encode()
    p.sign(privkey)
    d = p.encode()
    p2 = decode(d)
    assert isinstance(p2, Ping)
    assert p2.sender == address == p.sender
    assert p.nonce == p2.nonce
    assert p.signature == p2.signature
    assert p.cmdid == p.cmdid
    assert p.hash == p2.hash


def test_hash():
    msg = Ping(nonce=0).sign(privkey)
    d = msg.encode()
    msghash = sha3(d)
    msg2 = decode(d)
    assert sha3(msg2.encode()) == msghash


def test_ack():
    echo = sha3(privkey)
    msg = Ack(address, echo)
    assert msg.echo == echo
    d = msg.encode()
    msghash = sha3(d)
    msg2 = decode(d)
    assert msg2.echo == echo
    assert msg2.sender == address
    assert sha3(msg2.encode()) == msghash


def test_mediated_transfer():
    nonce = balance = 1
    asset = recipient = target = initiator = address
    hashlock = locksroot = sha3(address)
    amount = expiration = 1
    lock = Lock(amount, expiration, hashlock)

    d = lock.encode()
    assert Lock.decode(d) == lock

    msg = MediatedTransfer(nonce, asset, balance, recipient, locksroot,
                           lock, target, initiator, fee=0)
    msg.sign(privkey)
    dm = msg.encode()
    msg2 = decode(dm)
    assert msg2 == msg
    assert msg2.lock == lock
