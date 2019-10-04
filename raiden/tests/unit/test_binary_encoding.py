import random

import pytest

from raiden import constants
from raiden.exceptions import InvalidSignature
from raiden.messages.healthcheck import Ping
from raiden.messages.synchronization import Processed
from raiden.tests.utils import factories
from raiden.utils.signer import LocalSigner, recover

PRIVKEY, ADDRESS = factories.make_privkey_address()
signer = LocalSigner(PRIVKEY)


def test_signature():
    ping = Ping(
        nonce=0,
        current_protocol_version=constants.PROTOCOL_VERSION,
        signature=constants.EMPTY_SIGNATURE,
    )
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
    ping = Ping(
        nonce=0,
        current_protocol_version=constants.PROTOCOL_VERSION,
        signature=constants.EMPTY_SIGNATURE,
    )
    ping.sign(signer)
    assert ping.sender == ADDRESS


def test_hash():
    ping = Ping(
        nonce=0,
        current_protocol_version=constants.PROTOCOL_VERSION,
        signature=constants.EMPTY_SIGNATURE,
    )
    ping.sign(signer)


def test_processed():
    message_identifier = random.randint(0, constants.UINT64_MAX)
    processed_message = Processed(
        message_identifier=message_identifier, signature=constants.EMPTY_SIGNATURE
    )
    processed_message.sign(signer)
    assert processed_message.sender == ADDRESS
    assert processed_message.message_identifier == message_identifier


@pytest.mark.parametrize("amount", [0, constants.UINT256_MAX])
@pytest.mark.parametrize("payment_identifier", [0, constants.UINT64_MAX])
@pytest.mark.parametrize("nonce", [1, constants.UINT64_MAX])
@pytest.mark.parametrize("transferred_amount", [0, constants.UINT256_MAX])
@pytest.mark.parametrize("fee", [0, constants.UINT256_MAX])
def test_mediated_transfer_min_max(amount, payment_identifier, fee, nonce, transferred_amount):
    mediated_transfer = factories.create(
        factories.LockedTransferProperties(
            amount=amount,
            payment_identifier=payment_identifier,
            nonce=nonce,
            transferred_amount=transferred_amount,
            fee=fee,
        )
    )
    mediated_transfer._data_to_sign()  # Just test that packing works without exceptions.


@pytest.mark.parametrize("amount", [0, constants.UINT256_MAX])
@pytest.mark.parametrize("payment_identifier", [0, constants.UINT64_MAX])
@pytest.mark.parametrize("nonce", [1, constants.UINT64_MAX])
@pytest.mark.parametrize("transferred_amount", [0, constants.UINT256_MAX])
def test_refund_transfer_min_max(amount, payment_identifier, nonce, transferred_amount):
    refund_transfer = factories.create(
        factories.RefundTransferProperties(
            amount=amount,
            payment_identifier=payment_identifier,
            nonce=nonce,
            transferred_amount=transferred_amount,
        )
    )
    refund_transfer._data_to_sign()  # Just test that packing works without exceptions.
