# -*- coding: utf-8 -*-
import pytest
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
    assert roundtrip_serialize_mediated_transfer(mediated_transfer)


def make_lock_with_amount(amount):
    return Lock(amount, 1, "a" * 32)


def make_mediated_transfer_with_amount(amount):
    return MediatedTransfer(
        0,
        1,
        ADDRESS,
        amount,
        ADDRESS,
        "",
        make_lock_with_amount(amount),
        ADDRESS,
        ADDRESS,
        0
    )


def make_mediated_transfer_with_nonce(nonce):
    return MediatedTransfer(
        0,
        nonce,
        ADDRESS,
        1,
        ADDRESS,
        "",
        make_lock_with_amount(1),
        ADDRESS,
        ADDRESS,
        0
    )


def make_mediated_transfer_with_fee(fee):
    return MediatedTransfer(
        0,
        1,
        ADDRESS,
        1,
        ADDRESS,
        "",
        make_lock_with_amount(1),
        ADDRESS,
        ADDRESS,
        fee
    )


def roundtrip_serialize_mediated_transfer(mediated_transfer):
    mediated_transfer.sign(PRIVKEY, ADDRESS)
    decoded_mediated_transfer = decode(mediated_transfer.encode())
    assert decoded_mediated_transfer == mediated_transfer
    return True


@pytest.mark.parametrize("amount", [-1, 2 ** 256])
@pytest.mark.parametrize("make", [make_lock_with_amount,
                                  make_mediated_transfer_with_amount])
def test_amount_out_of_bounds(amount, make):
    with pytest.raises(ValueError):
        make(amount)


@pytest.mark.parametrize("amount", [0, 2 ** 256 - 1])
def test_mediated_transfer_amount_min_max(amount):
    mediated_transfer = make_mediated_transfer_with_amount(amount)
    assert roundtrip_serialize_mediated_transfer(mediated_transfer)


@pytest.mark.parametrize("nonce", [2 ** 64])
def test_mediated_transfer_nonce_out_of_bounds(nonce):
    with pytest.raises(ValueError):
        make_mediated_transfer_with_nonce(nonce)


@pytest.mark.parametrize("nonce", [2 ** 64 - 1])
def test_mediated_transfer_nonce_max(nonce):
    mediated_transfer = make_mediated_transfer_with_nonce(nonce)
    assert roundtrip_serialize_mediated_transfer(mediated_transfer)


@pytest.mark.parametrize("fee", [2 ** 256])
def test_mediated_transfer_fee_out_of_bounds(fee):
    with pytest.raises(ValueError):
        make_mediated_transfer_with_fee(fee)


@pytest.mark.parametrize("fee", [0, 2 ** 256 - 1])
def test_mediated_transfer_fee_min_max(fee):
    mediated_transfer = make_mediated_transfer_with_fee(fee)
    assert roundtrip_serialize_mediated_transfer(mediated_transfer)
