# -*- coding: utf-8 -*-
from raiden.messages import Ping, Ack, decode, Lock, MediatedTransfer
from raiden.utils import make_privkey_address, sha3

PRIVKEY, ADDRESS = make_privkey_address()


def test_signature():
    ping = Ping(nonce=0)
    ping.sign(PRIVKEY, ADDRESS)
    assert ping.sender == ADDRESS


def test_encoding():
    ping = Ping(nonce=0)
    ping.sign(PRIVKEY, ADDRESS)
    decoded_ping = decode(ping.encode())
    assert isinstance(decoded_ping, Ping)
    assert decoded_ping.sender == ADDRESS == ping.sender
    assert ping.nonce == decoded_ping.nonce
    assert ping.signature == decoded_ping.signature
    assert ping.cmdid == decoded_ping.cmdid
    assert ping.hash == decoded_ping.hash


def test_hash():
    ping = Ping(nonce=0)
    ping.sign(PRIVKEY, ADDRESS)
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
        1,  # TODO: fill in identifier
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
    mediated_transfer.sign(PRIVKEY, ADDRESS)
    decoded_mediated_transfer = decode(mediated_transfer.encode())
    assert decoded_mediated_transfer == mediated_transfer
