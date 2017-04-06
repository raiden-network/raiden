# -*- coding: utf-8 -*-
import pytest
from raiden.messages import Ping, Ack, decode, Lock, MediatedTransfer
from raiden.utils import make_privkey_address, sha3

PRIVKEY, ADDRESS = make_privkey_address()
INVALID_ADDRESSES = [
    ' ',
    ' ' * 19,
    ' ' * 21,
]


def make_lock_with_amount(amount):
    hashlock = 'a' * 32
    return Lock(amount, 1, hashlock)


def make_mediated_transfer(
        identifier=0,
        nonce=1,
        token=ADDRESS,
        transferred_amount=0,
        amount=1,
        locksroot='',
        recipient=ADDRESS,
        target=ADDRESS,
        initiator=ADDRESS,
        fee=0):

    return MediatedTransfer(
        identifier,
        nonce,
        token,
        transferred_amount,
        recipient,
        locksroot,
        make_lock_with_amount(amount),
        target,
        initiator,
        fee
    )


def roundtrip_serialize_mediated_transfer(mediated_transfer):
    mediated_transfer.sign(PRIVKEY, ADDRESS)
    decoded_mediated_transfer = decode(mediated_transfer.encode())
    assert decoded_mediated_transfer == mediated_transfer
    return True


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
    token = recipient = target = initiator = ADDRESS
    hashlock = locksroot = sha3(ADDRESS)
    amount = expiration = 1
    fee = 0

    lock = Lock(amount, expiration, hashlock)
    mediated_transfer = MediatedTransfer(
        1,  # TODO: fill in identifier
        nonce,
        token,
        balance,
        recipient,
        locksroot,
        lock,
        target,
        initiator,
        fee,
    )
    assert roundtrip_serialize_mediated_transfer(mediated_transfer)


@pytest.mark.parametrize('amount', [-1, 2 ** 256])
@pytest.mark.parametrize(
    'make',
    [
        make_lock_with_amount,
        make_mediated_transfer,
    ]
)
def test_amount_out_of_bounds(amount, make):
    with pytest.raises(ValueError):
        make(amount=amount)


@pytest.mark.parametrize('amount', [0, 2 ** 256 - 1])
@pytest.mark.parametrize('identifier', [0, 2 ** 64 - 1])
@pytest.mark.parametrize('nonce', [1, 2 ** 64 - 1])
@pytest.mark.parametrize('transferred_amount', [0, 2 ** 256 - 1])
@pytest.mark.parametrize('fee', [0, 2 ** 256 - 1])
def test_mediated_transfer_min_max(amount, identifier, fee, nonce, transferred_amount):
    mediated_transfer = make_mediated_transfer(
        amount=amount,
        identifier=identifier,
        nonce=nonce,
        fee=fee,
        transferred_amount=transferred_amount,
    )
    assert roundtrip_serialize_mediated_transfer(mediated_transfer)


# zero is used to indicate novalue in solidity
@pytest.mark.parametrize('nonce', [-1, 0, 2 ** 64])
@pytest.mark.parametrize('identifier', [-1, 2 ** 64])
@pytest.mark.parametrize('token', INVALID_ADDRESSES)
@pytest.mark.parametrize('recipient', INVALID_ADDRESSES)
@pytest.mark.parametrize('target', INVALID_ADDRESSES)
@pytest.mark.parametrize('initiator', INVALID_ADDRESSES)
@pytest.mark.parametrize('transferred_amount', [-1, 2 ** 256])
@pytest.mark.parametrize('fee', [2 ** 256])
def test_mediated_transfer_out_of_bounds_values(
        nonce,
        identifier,
        token,
        recipient,
        target,
        initiator,
        transferred_amount,
        fee):

    with pytest.raises(ValueError):
        make_mediated_transfer(
            nonce=nonce,
            identifier=identifier,
            token=token,
            recipient=recipient,
            target=target,
            initiator=initiator,
            transferred_amount=transferred_amount,
            fee=fee,
        )
