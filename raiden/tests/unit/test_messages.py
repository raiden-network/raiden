# -*- coding: utf-8 -*-

import pytest

from raiden.messages import (
    decode,
    Ack,
    Ping,
)
from raiden.utils import make_privkey_address, sha3
from raiden.tests.utils.messages import (
    make_direct_transfer,
    make_lock,
    make_mediated_transfer,
    make_refund_transfer,
    MEDIATED_TRANSFER_INVALID_VALUES,
    REFUND_TRANSFER_INVALID_VALUES,
    DIRECT_TRANSFER_INVALID_VALUES,
)

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


@pytest.mark.parametrize('amount', [-1, 2 ** 256])
@pytest.mark.parametrize(
    'make',
    [
        make_lock,
        make_mediated_transfer,
    ]
)
def test_amount_out_of_bounds(amount, make):
    with pytest.raises(ValueError):
        make(amount=amount)


@pytest.mark.parametrize('identifier', [0, 2 ** 64 - 1])
@pytest.mark.parametrize('nonce', [1, 2 ** 64 - 1])
@pytest.mark.parametrize('transferred_amount', [0, 2 ** 256 - 1])
def test_direct_transfer_min_max(identifier, nonce, transferred_amount):
    direct_transfer = make_direct_transfer(
        identifier=identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
    )

    direct_transfer.sign(PRIVKEY, ADDRESS)
    assert decode(direct_transfer.encode()) == direct_transfer


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

    mediated_transfer.sign(PRIVKEY, ADDRESS)
    assert decode(mediated_transfer.encode()) == mediated_transfer


@pytest.mark.parametrize('amount', [0, 2 ** 256 - 1])
@pytest.mark.parametrize('identifier', [0, 2 ** 64 - 1])
@pytest.mark.parametrize('nonce', [1, 2 ** 64 - 1])
@pytest.mark.parametrize('transferred_amount', [0, 2 ** 256 - 1])
def test_refund_transfer_min_max(amount, identifier, nonce, transferred_amount):
    refund_transfer = make_refund_transfer(
        amount=amount,
        identifier=identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
    )

    refund_transfer.sign(PRIVKEY, ADDRESS)
    assert decode(refund_transfer.encode()) == refund_transfer


@pytest.mark.parametrize('args', MEDIATED_TRANSFER_INVALID_VALUES)
def test_mediated_transfer_out_of_bounds_values(args):
    with pytest.raises(ValueError):
        make_mediated_transfer(**args)


@pytest.mark.parametrize('args', REFUND_TRANSFER_INVALID_VALUES)
def test_refund_transfer_out_of_bounds_values(args):
    with pytest.raises(ValueError):
        make_refund_transfer(**args)


@pytest.mark.parametrize('args', DIRECT_TRANSFER_INVALID_VALUES)
def test_direct_transfer_out_of_bounds_values(args):
    with pytest.raises(ValueError):
        make_direct_transfer(**args)
