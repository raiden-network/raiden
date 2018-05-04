# -*- coding: utf-8 -*-
import random

import pytest

from raiden.messages import (
    decode,
    Processed,
    Ping,
)
from raiden.constants import UINT256_MAX, UINT64_MAX
from raiden.utils import sha3
from raiden.tests.utils.messages import (
    make_direct_transfer,
    make_mediated_transfer,
    make_refund_transfer,
)
from raiden.tests.utils.factories import make_privkey_address

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


def test_processed():
    processed_message_identifier = random.randint(0, UINT64_MAX)
    processed_message = Processed(ADDRESS, processed_message_identifier)

    assert processed_message.processed_message_identifier == processed_message_identifier

    data = processed_message.encode()
    decoded_processed_message = decode(data)

    assert decoded_processed_message.processed_message_identifier == processed_message_identifier
    assert processed_message.processed_message_identifier == processed_message_identifier
    assert decoded_processed_message.sender == processed_message.sender
    assert sha3(decoded_processed_message.encode()) == sha3(data)


@pytest.mark.parametrize('payment_identifier', [0, UINT64_MAX])
@pytest.mark.parametrize('nonce', [1, UINT64_MAX])
@pytest.mark.parametrize('transferred_amount', [0, UINT256_MAX])
def test_direct_transfer_min_max(payment_identifier, nonce, transferred_amount):
    direct_transfer = make_direct_transfer(
        payment_identifier=payment_identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
    )

    direct_transfer.sign(PRIVKEY, ADDRESS)
    assert decode(direct_transfer.encode()) == direct_transfer


@pytest.mark.parametrize('amount', [0, UINT256_MAX])
@pytest.mark.parametrize('payment_identifier', [0, UINT64_MAX])
@pytest.mark.parametrize('nonce', [1, UINT64_MAX])
@pytest.mark.parametrize('transferred_amount', [0, UINT256_MAX])
@pytest.mark.parametrize('fee', [0, UINT256_MAX])
def test_mediated_transfer_min_max(amount, payment_identifier, fee, nonce, transferred_amount):
    mediated_transfer = make_mediated_transfer(
        amount=amount,
        payment_identifier=payment_identifier,
        nonce=nonce,
        fee=fee,
        transferred_amount=transferred_amount,
    )

    mediated_transfer.sign(PRIVKEY, ADDRESS)
    assert decode(mediated_transfer.encode()) == mediated_transfer


@pytest.mark.parametrize('amount', [0, UINT256_MAX])
@pytest.mark.parametrize('payment_identifier', [0, UINT64_MAX])
@pytest.mark.parametrize('nonce', [1, UINT64_MAX])
@pytest.mark.parametrize('transferred_amount', [0, UINT256_MAX])
def test_refund_transfer_min_max(amount, payment_identifier, nonce, transferred_amount):
    refund_transfer = make_refund_transfer(
        amount=amount,
        payment_identifier=payment_identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
    )

    refund_transfer.sign(PRIVKEY, ADDRESS)
    assert decode(refund_transfer.encode()) == refund_transfer
