# -*- coding: utf-8 -*-
import pytest
from ethereum.tools import tester
from ethereum.tools.tester import TransactionFailed
from coincurve import PrivateKey

from raiden.messages import (
    EMPTY_MERKLE_ROOT,
    DirectTransfer,
)
from raiden.tests.utils.messages import (
    make_direct_transfer,
)
from raiden.tests.utils.transfer import make_direct_transfer_from_channel
from raiden.utils import privatekey_to_address, sha3, event_decoder, address_encoder
from raiden.tests.utils.factories import make_address


def test_close_event(tester_chain, tester_nettingcontracts, tester_events):
    """ The event ChannelClosed is emitted when close is called. """
    pkey0, _, nettingchannel = tester_nettingcontracts[0]
    address = privatekey_to_address(pkey0)

    previous_events = list(tester_events)
    nettingchannel.close(sender=pkey0)
    assert len(previous_events) + 1 == len(tester_events)

    close_event = event_decoder(tester_events[-1], nettingchannel.translator)
    assert close_event == {
        '_event_type': b'ChannelClosed',
        'closing_address': address_encoder(address),
    }


def test_close_first_participant_can_close(tester_chain, tester_nettingcontracts):
    """ First participant can close an unused channel. """
    pkey0, _, nettingchannel = tester_nettingcontracts[0]
    address0 = privatekey_to_address(pkey0)

    block_number = tester_chain.block.number
    nettingchannel.close(sender=pkey0)

    assert nettingchannel.closed(sender=pkey0) == block_number
    assert nettingchannel.closingAddress(sender=pkey0) == address_encoder(address0)


def test_close_second_participant_can_close(tester_chain, tester_nettingcontracts):
    """ Second participant can close an unused channel. """
    _, pkey1, nettingchannel = tester_nettingcontracts[0]
    address1 = privatekey_to_address(pkey1)

    closed_block_number = tester_chain.block.number
    nettingchannel.close(sender=pkey1)

    assert nettingchannel.closed(sender=pkey1) == closed_block_number
    assert nettingchannel.closingAddress(sender=pkey1) == address_encoder(address1)


def test_close_only_participant_can_close(tester_nettingcontracts):
    """ Only the participants may call close. """
    # Third party close is discussed on issue #182
    _, _, nettingchannel = tester_nettingcontracts[0]

    nonparticipant_key = tester.k3
    with pytest.raises(TransactionFailed):
        nettingchannel.close(sender=nonparticipant_key)


def test_close_first_argument_is_for_partner_transfer(tester_chain, tester_channels):
    """ Close must not accept a transfer from the closing address. """
    pkey0, _, nettingchannel, channel0, channel1 = tester_channels[0]

    block_number = tester_chain.block.number
    transfer0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount=90,
        pkey=pkey0,
    )

    transfer0_hash = sha3(transfer0.packed().data[:-65])
    with pytest.raises(TransactionFailed):
        nettingchannel.close(
            transfer0.nonce,
            transfer0.transferred_amount,
            transfer0.locksroot,
            transfer0_hash,
            transfer0.signature,
            sender=pkey0,
        )


@pytest.mark.parametrize('number_of_nodes', [3])
def test_close_accepts_only_transfer_from_participants(tester_channels, private_keys):
    """ Close must not accept a transfer signed by a non participant. """
    pkey0, _, nettingchannel, channel0, _ = tester_channels[0]
    nonparticipant_key = private_keys[2]
    opened_block = nettingchannel.opened(sender=pkey0)

    # make a transfer where pkey0 is the target
    transfer_nonparticipant = DirectTransfer(
        identifier=1,
        nonce=1 + (opened_block * (2 ** 32)),
        token=channel0.token_address,
        channel=channel0.channel_address,
        transferred_amount=10,
        recipient=channel0.our_address,
        locksroot=EMPTY_MERKLE_ROOT,
    )

    nonparticipant_address = privatekey_to_address(nonparticipant_key)
    nonparticipant_sign_key = PrivateKey(nonparticipant_key)

    transfer_nonparticipant.sign(nonparticipant_sign_key, nonparticipant_address)

    transfer_nonparticipant_hash = sha3(transfer_nonparticipant.packed().data[:-65])
    with pytest.raises(TransactionFailed):
        nettingchannel.close(
            transfer_nonparticipant.nonce,
            transfer_nonparticipant.transferred_amount,
            transfer_nonparticipant.locksroot,
            transfer_nonparticipant_hash,
            transfer_nonparticipant.signature,
            sender=pkey0,
        )


@pytest.mark.parametrize('number_of_nodes', [2])
def test_close_wrong_channel(tester_channels):
    """ Close must not accept a transfer aimed at a different channel. """
    pkey0, pkey1, nettingchannel, channel0, _ = tester_channels[0]
    opened_block = nettingchannel.opened(sender=pkey0)
    wrong_address = make_address()

    # make a transfer where the recipient is totally wrong
    transfer_wrong_channel = DirectTransfer(
        identifier=1,
        nonce=1 + (opened_block * (2 ** 32)),
        token=channel0.token_address,
        channel=wrong_address,
        transferred_amount=10,
        recipient=channel0.our_address,
        locksroot=EMPTY_MERKLE_ROOT,
    )

    transfer_wrong_channel.sign(PrivateKey(pkey1), privatekey_to_address(pkey1))

    transfer_wrong_channel_hash = sha3(transfer_wrong_channel.packed().data[:-65])
    with pytest.raises(TransactionFailed):
        nettingchannel.close(
            transfer_wrong_channel.nonce,
            transfer_wrong_channel.transferred_amount,
            transfer_wrong_channel.locksroot,
            transfer_wrong_channel_hash,
            transfer_wrong_channel.signature,
            sender=pkey0,
        )


def test_close_called_multiple_times(tester_chain, tester_nettingcontracts):
    """ A channel can be closed only once. """
    pkey0, pkey1, nettingchannel = tester_nettingcontracts[0]
    address0 = privatekey_to_address(pkey0)

    closed_block_number = tester_chain.block.number
    nettingchannel.close(sender=pkey0)

    with pytest.raises(TransactionFailed):
        nettingchannel.close(sender=pkey0)

    with pytest.raises(TransactionFailed):
        nettingchannel.close(sender=pkey1)

    assert nettingchannel.closed(sender=pkey0) == closed_block_number
    assert nettingchannel.closingAddress(sender=pkey0) == address_encoder(address0)


@pytest.mark.xfail(reason='Issue: #292')
def test_close_valid_tranfer_different_token(
        tester_chain,
        tester_nettingcontracts,
        token_amount,
        tester_events):
    """ Valid messages from a different channel must be rejected. """
    pkey0, pkey1, nettingchannel = tester_nettingcontracts[0]

    from raiden.tests.fixtures.tester import (
        tester_token,
        tester_token_address,
    )

    private_keys = [pkey0, pkey1]
    other_token = tester_token(
        token_amount,
        private_keys,
        tester_chain,
        tester_token_address(private_keys, token_amount, tester_chain),
        tester_events,
    )

    opened_block = nettingchannel.opened(sender=pkey0)
    nonce = 1 + (opened_block * (2 ** 32))
    direct_transfer_other_token = make_direct_transfer(
        nonce=nonce,
        token=other_token.address,
    )

    address = privatekey_to_address(pkey0)
    sign_key = PrivateKey(pkey0)
    direct_transfer_other_token.sign(sign_key, address)

    direct_transfer_other_token_hash = sha3(direct_transfer_other_token.encode()[:-65])
    with pytest.raises(TransactionFailed):
        nettingchannel.close(
            direct_transfer_other_token.nonce,
            direct_transfer_other_token.transferred_amount,
            direct_transfer_other_token.locksroot,
            direct_transfer_other_token_hash,
            direct_transfer_other_token.signature,
            sender=pkey1,
        )


def test_close_tampered_identifier(tester_chain, tester_channels):
    """ Messages with a tampered identifier must be rejected. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    block_number = tester_chain.block.number
    transfer0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount=90,
        pkey=pkey0,
    )
    transfer0_data = transfer0.encode()

    tampered_transfer = DirectTransfer.decode(transfer0_data)
    tampered_transfer.identifier += 1

    tampered_transfer_hash = sha3(tampered_transfer.encode()[:-65])
    with pytest.raises(TransactionFailed):
        nettingchannel.close(
            tampered_transfer.nonce,
            tampered_transfer.transferred_amount,
            tampered_transfer.locksroot,
            tampered_transfer_hash,
            tampered_transfer.signature,
            sender=pkey1,
        )


def test_close_tampered_nonce(tester_chain, tester_channels):
    """ Messages with a tampered nonce must be rejected. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    block_number = tester_chain.block.number
    transfer0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount=90,
        pkey=pkey0,
    )
    transfer0_data = transfer0.encode()

    tampered_transfer = DirectTransfer.decode(transfer0_data)
    tampered_transfer.nonce += 1

    tampered_transfer_hash = sha3(tampered_transfer.encode()[:-65])
    with pytest.raises(TransactionFailed):
        nettingchannel.close(
            tampered_transfer.nonce,
            tampered_transfer.transferred_amount,
            tampered_transfer.locksroot,
            tampered_transfer_hash,
            tampered_transfer.signature,
            sender=pkey1,
        )
