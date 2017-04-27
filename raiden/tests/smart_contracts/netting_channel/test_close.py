# -*- coding: utf-8 -*-
import pytest
from ethereum import tester
from ethereum.tester import TransactionFailed
from ethereum.utils import encode_hex
from coincurve import PrivateKey

from raiden.messages import DirectTransfer
from raiden.tests.utils.messages import (
    make_direct_transfer,
)
from raiden.tests.utils.transfer import make_direct_transfer_from_channel
from raiden.utils import privatekey_to_address


def test_close_event(tester_state, tester_nettingcontracts, tester_events):
    """ The event ChannelClosed is emitted when close is called. """
    pkey0, _, nettingchannel = tester_nettingcontracts[0]
    address = privatekey_to_address(pkey0)

    previous_events = list(tester_events)
    nettingchannel.close('', sender=pkey0)
    assert len(previous_events) + 1 == len(tester_events)

    block_number = tester_state.block.number
    close_event = tester_events[-1]
    assert close_event == {
        '_event_type': 'ChannelClosed',
        'closing_address': encode_hex(address),
        'block_number': block_number,
    }


def test_close_first_participant_can_close(tester_state, tester_nettingcontracts):
    """ First participant can close an unused channel. """
    pkey0, _, nettingchannel = tester_nettingcontracts[0]
    address0 = privatekey_to_address(pkey0)

    block_number = tester_state.block.number
    nettingchannel.close('', sender=pkey0)

    assert nettingchannel.closed(sender=pkey0) == block_number
    assert nettingchannel.closingAddress(sender=pkey0) == encode_hex(address0)


def test_close_second_participant_can_close(tester_state, tester_nettingcontracts):
    """ Second participant can close an unused channel. """
    _, pkey1, nettingchannel = tester_nettingcontracts[0]
    address1 = privatekey_to_address(pkey1)

    closed_block_number = tester_state.block.number
    nettingchannel.close('', sender=pkey1)

    assert nettingchannel.closed(sender=pkey1) == closed_block_number
    assert nettingchannel.closingAddress(sender=pkey1) == encode_hex(address1)


def test_close_only_participant_can_close(tester_nettingcontracts):
    """ Only the participants may call close. """
    # Third party close is discussed on issue #182
    _, _, nettingchannel = tester_nettingcontracts[0]

    nonparticipant_key = tester.k3
    with pytest.raises(TransactionFailed):
        nettingchannel.close('', sender=nonparticipant_key)


def test_close_first_argument_is_for_partner_transfer(tester_channels):
    """ Close must not accept a transfer from the closing address. """
    pkey0, _, nettingchannel, channel0, channel1 = tester_channels[0]

    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount=90, pkey=pkey0)
    transfer0_data = str(transfer0.packed().data)

    with pytest.raises(TransactionFailed):
        nettingchannel.close(transfer0_data, sender=pkey0)


@pytest.mark.parametrize('number_of_nodes', [3])
def test_close_accepts_only_transfer_from_participants(tester_channels, private_keys):
    """ Close must not accept a transfer from a non participant. """
    pkey0, _, nettingchannel, channel0, _ = tester_channels[0]
    nonparticipant_key = private_keys[2]

    # make a transfer where pkey0 is the target
    transfer_nonparticipant = DirectTransfer(
        identifier=1,
        nonce=1,
        token=channel0.token_address,
        transferred_amount=10,
        recipient=channel0.our_address,
        locksroot='',
    )

    nonparticipant_address = privatekey_to_address(nonparticipant_key)
    nonparticipant_sign_key = PrivateKey(nonparticipant_key)

    transfer_nonparticipant.sign(nonparticipant_sign_key, nonparticipant_address)
    transfer_nonparticipant_data = str(transfer_nonparticipant.packed().data)

    with pytest.raises(TransactionFailed):
        nettingchannel.close(transfer_nonparticipant_data, sender=pkey0)


def test_close_called_multiple_times(tester_state, tester_nettingcontracts):
    """ A channel can be closed only once. """
    pkey0, pkey1, nettingchannel = tester_nettingcontracts[0]
    address0 = privatekey_to_address(pkey0)

    closed_block_number = tester_state.block.number
    nettingchannel.close('', sender=pkey0)

    with pytest.raises(TransactionFailed):
        nettingchannel.close('', sender=pkey0)

    with pytest.raises(TransactionFailed):
        nettingchannel.close('', sender=pkey1)

    assert nettingchannel.closed(sender=pkey0) == closed_block_number
    assert nettingchannel.closingAddress(sender=pkey0) == encode_hex(address0)


@pytest.mark.xfail(reason='Issue: #292')
def test_close_valid_tranfer_different_token(
        tester_state,
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
        tester_state,
        tester_token_address(private_keys, token_amount, tester_state),
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

    direct_transfer_data = direct_transfer_other_token.encode()

    with pytest.raises(TransactionFailed):
        nettingchannel.close(direct_transfer_data, sender=pkey1)


def test_close_tampered_identifier(tester_state, tester_channels):
    """ Messages with a tampered identifier must be rejected. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount=90, pkey=pkey0)
    transfer0_data = transfer0.encode()

    tampered_transfer = DirectTransfer.decode(transfer0_data)
    tampered_transfer.identifier += 1
    tampered_transfer_data = tampered_transfer.encode()

    with pytest.raises(TransactionFailed):
        nettingchannel.close(tampered_transfer_data, sender=pkey1)


def test_close_tampered_nonce(tester_state, tester_channels):
    """ Messages with a tampered nonce must be rejected. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount=90, pkey=pkey0)
    transfer0_data = transfer0.encode()

    tampered_transfer = DirectTransfer.decode(transfer0_data)
    tampered_transfer.nonce += 1
    tampered_transfer_data = tampered_transfer.encode()

    with pytest.raises(TransactionFailed):
        nettingchannel.close(tampered_transfer_data, sender=pkey1)
