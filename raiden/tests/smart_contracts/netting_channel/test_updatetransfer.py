# -*- coding: utf-8 -*-
import pytest
from ethereum.tools.tester import TransactionFailed
from coincurve import PrivateKey

from raiden.messages import (
    EMPTY_MERKLE_ROOT,
    DirectTransfer,
)
from raiden.utils import privatekey_to_address, sha3, event_decoder, address_encoder
from raiden.tests.utils.transfer import make_direct_transfer_from_channel
from raiden.tests.utils.factories import make_address


def test_transfer_update_event(tester_chain, tester_channels, tester_events):
    """ The event TransferUpdated is emitted after a successful call to
    updateTransfer.
    """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]
    address1 = privatekey_to_address(pkey1)

    block_number = tester_chain.block.number
    direct0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount=90,
        pkey=pkey0,
    )

    nettingchannel.close(sender=pkey0)
    previous_events = list(tester_events)

    direct0_hash = sha3(direct0.packed().data[:-65])
    nettingchannel.updateTransfer(
        direct0.nonce,
        direct0.transferred_amount,
        direct0.locksroot,
        direct0_hash,
        direct0.signature,
        sender=pkey1,
    )
    assert len(previous_events) + 1 == len(tester_events)

    last_event = event_decoder(tester_events[-1], nettingchannel.translator)
    assert last_event == {
        '_event_type': b'TransferUpdated',
        'node_address': address_encoder(address1),
    }


def test_update_fails_on_open_channel(tester_chain, tester_channels):
    """ Cannot call updateTransfer on a open channel. """
    pkey0, _, nettingchannel, channel0, channel1 = tester_channels[0]

    block_number = tester_chain.block.number
    transfer0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount=10,
        pkey=pkey0,
    )

    transfer0_hash = sha3(transfer0.packed().data[:-65])
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(
            transfer0.nonce,
            transfer0.transferred_amount,
            transfer0.locksroot,
            transfer0_hash,
            transfer0.signature,
            sender=pkey0,
        )


def test_update_not_allowed_after_settlement_period(settle_timeout, tester_channels, tester_chain):
    """ updateTransfer cannot be called after the settlement period. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    block_number = tester_chain.block.number
    direct0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount=70,
        pkey=pkey0,
    )

    nettingchannel.close(sender=pkey0)
    tester_chain.mine(number_of_blocks=settle_timeout + 1)

    direct0_hash = sha3(direct0.packed().data[:-65])
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(
            direct0.nonce,
            direct0.transferred_amount,
            direct0.locksroot,
            direct0_hash,
            direct0.signature,
            sender=pkey1,
        )


def test_update_not_allowed_for_the_closing_address(tester_chain, tester_channels):
    """ Closing address cannot call updateTransfer. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    block_number = tester_chain.block.number
    transfer0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount=10,
        pkey=pkey0,
    )

    block_number = tester_chain.block.number
    transfer1 = make_direct_transfer_from_channel(
        block_number,
        channel1,
        channel0,
        amount=10,
        pkey=pkey1,
    )

    nettingchannel.close(sender=pkey0)

    # do not accept a transfer from the party that closed
    transfer0_hash = sha3(transfer0.packed().data[:-65])
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(
            transfer0.nonce,
            transfer0.transferred_amount,
            transfer0.locksroot,
            transfer0_hash,
            transfer0.signature,
            sender=pkey0,
        )

    # nor a transfer from the partner
    transfer1_hash = sha3(transfer1.packed().data[:-65])
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(
            transfer1.nonce,
            transfer1.transferred_amount,
            transfer1.locksroot,
            transfer1_hash,
            transfer1.signature,
            sender=pkey0,
        )


@pytest.mark.parametrize('number_of_nodes', [3])
def test_update_must_fail_with_a_nonparticipant_transfer(tester_channels, private_keys):
    """ updateTransfer must not accept a transfer from a non participant. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]
    nonparticipant_key = private_keys[2]
    opened_block = nettingchannel.opened(sender=pkey0)

    # make a transfer where pkey1 is the target
    transfer_nonparticipant = DirectTransfer(
        identifier=1,
        nonce=1 + (opened_block * (2 ** 32)),
        token=channel0.token_address,
        channel=channel0.channel_address,
        transferred_amount=10,
        recipient=channel1.our_address,
        locksroot=EMPTY_MERKLE_ROOT,
    )

    nonparticipant_address = privatekey_to_address(nonparticipant_key)
    nonparticipant_sign_key = PrivateKey(nonparticipant_key)

    transfer_nonparticipant.sign(nonparticipant_sign_key, nonparticipant_address)

    nettingchannel.close(sender=pkey0)

    transfer_nonparticipant_hash = sha3(transfer_nonparticipant.packed().data[:-65])
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(
            transfer_nonparticipant.nonce,
            transfer_nonparticipant.transferred_amount,
            transfer_nonparticipant.locksroot,
            transfer_nonparticipant_hash,
            transfer_nonparticipant.signature,
            sender=pkey1,
        )


@pytest.mark.parametrize('number_of_nodes', [3])
def test_update_must_fail_with_a_channel_address(tester_channels, private_keys):
    """ updateTransfer must not accept a transfer signed with the wrong channel address. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]
    opened_block = nettingchannel.opened(sender=pkey0)
    wrong_channel = make_address()

    # make a transfer where pkey1 is the target
    transfer_wrong_recipient = DirectTransfer(
        identifier=1,
        nonce=1 + (opened_block * (2 ** 32)),
        token=channel0.token_address,
        channel=wrong_channel,
        transferred_amount=10,
        recipient=channel1.our_address,
        locksroot=EMPTY_MERKLE_ROOT,
    )

    our_address = privatekey_to_address(pkey0)
    our_sign_key = PrivateKey(pkey0)

    transfer_wrong_recipient.sign(our_sign_key, our_address)

    nettingchannel.close(sender=pkey0)

    transfer_wrong_recipient_hash = sha3(transfer_wrong_recipient.packed().data[:-65])
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(
            transfer_wrong_recipient.nonce,
            transfer_wrong_recipient.transferred_amount,
            transfer_wrong_recipient.locksroot,
            transfer_wrong_recipient_hash,
            transfer_wrong_recipient.signature,
            sender=pkey1,
        )


def test_update_called_multiple_times_same_transfer(tester_chain, tester_channels):
    """ updateTransfer can be called only once. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    block_number = tester_chain.block.number
    transfer0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount=10,
        pkey=pkey0,
    )

    nettingchannel.close(sender=pkey0)

    transfer0_hash = sha3(transfer0.packed().data[:-65])
    nettingchannel.updateTransfer(
        transfer0.nonce,
        transfer0.transferred_amount,
        transfer0.locksroot,
        transfer0_hash,
        transfer0.signature,
        sender=pkey1,
    )

    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(
            transfer0.nonce,
            transfer0.transferred_amount,
            transfer0.locksroot,
            transfer0_hash,
            transfer0.signature,
            sender=pkey1,
        )


def test_update_called_multiple_times_new_transfer(tester_chain, tester_channels):
    """ updateTransfer second call must fail even if there is a new transfer. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    block_number = tester_chain.block.number
    transfer0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount=10,
        pkey=pkey0,
    )

    block_number = tester_chain.block.number
    transfer1 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount=10,
        pkey=pkey0,
    )

    nettingchannel.close(sender=pkey0)

    transfer0_hash = sha3(transfer0.packed().data[:-65])
    nettingchannel.updateTransfer(
        transfer0.nonce,
        transfer0.transferred_amount,
        transfer0.locksroot,
        transfer0_hash,
        transfer0.signature,
        sender=pkey1,
    )

    transfer1_hash = sha3(transfer1.packed().data[:-65])
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(
            transfer1.nonce,
            transfer1.transferred_amount,
            transfer1.locksroot,
            transfer1_hash,
            transfer1.signature,
            sender=pkey1,
        )


def test_update_called_multiple_times_older_transfer(tester_chain, tester_channels):
    """ updateTransfer second call must fail even if called with an older transfer. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    block_number = tester_chain.block.number
    transfer0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount=10,
        pkey=pkey0,
    )

    block_number = tester_chain.block.number
    transfer1 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount=10,
        pkey=pkey0,
    )

    nettingchannel.close(sender=pkey0)

    transfer1_hash = sha3(transfer1.packed().data[:-65])
    nettingchannel.updateTransfer(
        transfer1.nonce,
        transfer1.transferred_amount,
        transfer1.locksroot,
        transfer1_hash,
        transfer1.signature,
        sender=pkey1,
    )

    transfer0_hash = sha3(transfer0.packed().data[:-65])
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(
            transfer0.nonce,
            transfer0.transferred_amount,
            transfer0.locksroot,
            transfer0_hash,
            transfer0.signature,
            sender=pkey1,
        )
