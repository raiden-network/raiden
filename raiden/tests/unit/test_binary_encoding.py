import random

import pytest

from raiden import constants
from raiden.exceptions import InvalidSignature
from raiden.messages import Ping, Processed, decode
from raiden.tests.utils.factories import make_privkey_address
from raiden.tests.utils.messages import make_mediated_transfer, make_refund_transfer
from raiden.utils import sha3
from raiden.utils.signer import LocalSigner, recover

PRIVKEY, ADDRESS = make_privkey_address()
signer = LocalSigner(PRIVKEY)


def test_signature():
    ping = Ping(nonce=0, current_protocol_version=constants.PROTOCOL_VERSION)
    ping.sign(signer)
    assert ping.sender == ADDRESS

    # test that the valid v values are accepted
    message_data = ping._data_to_sign()
    # This signature will sometimes end up with v being 0, sometimes 1
    signature = signer.sign(data=message_data, v=0)
    assert ADDRESS == recover(message_data, signature)
    # This signature will sometimes end up with v being 27, sometimes 28
    signature = signer.sign(data=message_data, v=27)
    assert ADDRESS == recover(message_data, signature)

    # test that other v values are rejected
    signature = signature[:-1] + bytes([29])
    with pytest.raises(InvalidSignature):
        recover(message_data, signature)
    signature = signature[:-1] + bytes([37])
    with pytest.raises(InvalidSignature):
        recover(message_data, signature)
    signature = signature[:-1] + bytes([38])
    with pytest.raises(InvalidSignature):
        recover(message_data, signature)


def test_encoding():
    ping = Ping(nonce=0, current_protocol_version=constants.PROTOCOL_VERSION)
    ping.sign(signer)
    decoded_ping = decode(ping.encode())
    assert isinstance(decoded_ping, Ping)
    assert decoded_ping.sender == ADDRESS == ping.sender
    assert ping.nonce == decoded_ping.nonce
    assert ping.signature == decoded_ping.signature
    assert ping.cmdid == decoded_ping.cmdid
    assert ping.hash == decoded_ping.hash


def test_hash():
    ping = Ping(nonce=0, current_protocol_version=constants.PROTOCOL_VERSION)
    ping.sign(signer)
    data = ping.encode()
    msghash = sha3(data)
    decoded_ping = decode(data)
    assert sha3(decoded_ping.encode()) == msghash


def test_processed():
    message_identifier = random.randint(0, constants.UINT64_MAX)
    processed_message = Processed(message_identifier=message_identifier)
    processed_message.sign(signer)
    assert processed_message.sender == ADDRESS

    assert processed_message.message_identifier == message_identifier

    data = processed_message.encode()
    decoded_processed_message = decode(data)

    assert decoded_processed_message.message_identifier == message_identifier
    assert processed_message.message_identifier == message_identifier
    assert decoded_processed_message.sender == processed_message.sender
    assert sha3(decoded_processed_message.encode()) == sha3(data)


@pytest.mark.parametrize('amount', [0, constants.UINT256_MAX])
@pytest.mark.parametrize('payment_identifier', [0, constants.UINT64_MAX])
@pytest.mark.parametrize('nonce', [1, constants.UINT64_MAX])
@pytest.mark.parametrize('transferred_amount', [0, constants.UINT256_MAX])
@pytest.mark.parametrize('fee', [0, constants.UINT256_MAX])
def test_mediated_transfer_min_max(amount, payment_identifier, fee, nonce, transferred_amount):
    mediated_transfer = make_mediated_transfer(
        amount=amount,
        payment_identifier=payment_identifier,
        nonce=nonce,
        fee=fee,
        transferred_amount=transferred_amount,
    )

    mediated_transfer.sign(signer)
    assert mediated_transfer.sender == ADDRESS
    assert decode(mediated_transfer.encode()) == mediated_transfer


@pytest.mark.parametrize('amount', [0, constants.UINT256_MAX])
@pytest.mark.parametrize('payment_identifier', [0, constants.UINT64_MAX])
@pytest.mark.parametrize('nonce', [1, constants.UINT64_MAX])
@pytest.mark.parametrize('transferred_amount', [0, constants.UINT256_MAX])
def test_refund_transfer_min_max(amount, payment_identifier, nonce, transferred_amount):
    refund_transfer = make_refund_transfer(
        amount=amount,
        payment_identifier=payment_identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
    )

    refund_transfer.sign(signer)
    assert refund_transfer.sender == ADDRESS
    assert decode(refund_transfer.encode()) == refund_transfer
