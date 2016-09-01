# -*- coding: utf8 -*-
from raiden.messages import Ping, Ack, decode, Lock, MediatedTransfer
from raiden.utils import privatekey_to_address, sha3

PRIVKEY = 'x' * 32
ADDRESS = privatekey_to_address(PRIVKEY)


def test_signature():
    ping = Ping(nonce=0)
    ping.sign(PRIVKEY)
    assert ping.sender == ADDRESS


def test_encoding():
    ping = Ping(nonce=0)
    ping.sign(PRIVKEY)
    decoded_ping = decode(ping.encode())
    assert isinstance(decoded_ping, Ping)
    assert decoded_ping.sender == ADDRESS == ping.sender
    assert ping.nonce == decoded_ping.nonce
    assert ping.signature == decoded_ping.signature
    assert ping.cmdid == decoded_ping.cmdid
    assert ping.hash == decoded_ping.hash


def test_hash():
    ping = Ping(nonce=0)
    ping.sign(PRIVKEY)
    data = ping.encode()
    msghash = sha3(data)
    decoded_ping = decode(data)
    assert sha3(decoded_ping.encode()) == msghash


def test_ack():
    echo = sha3(PRIVKEY)
    ack = Ack(ADDRESS, echo)
    assert ack.echo == echo
    data = ack.encode()
    msghash = sha3(data)
    decoded_ack = decode(data)
    assert decoded_ack.echo == ack.echo
    assert decoded_ack.sender == ack.sender
    assert sha3(decoded_ack.encode()) == msghash


def test_mediated_transfer():
    nonce = balance = 1
    asset = recipient = target = initiator = ADDRESS
    hashlock = locksroot = sha3(ADDRESS)
    amount = expiration = 1
    fee = 0

    lock = Lock(amount, expiration, hashlock)
    mediated_transfer = MediatedTransfer(
        nonce,
        asset,
        balance,
        recipient,
        locksroot,
        lock,
        target,
        initiator,
        fee,
    )
    mediated_transfer.sign(PRIVKEY)
    decoded_mediated_transfer = decode(mediated_transfer.encode())
    assert decoded_mediated_transfer == mediated_transfer
