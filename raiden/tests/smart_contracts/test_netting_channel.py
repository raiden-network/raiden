# -*- coding: utf-8 -*-
# pylint: disable=no-member,too-many-arguments,too-many-lines,invalid-name,too-many-locals
from __future__ import division

import pytest
from ethereum import abi, tester
from ethereum.tester import TransactionFailed
from ethereum.utils import encode_hex
from secp256k1 import PrivateKey

from raiden.encoding.signing import GLOBAL_CTX
from raiden.messages import Lock, DirectTransfer, MediatedTransfer
from raiden.mtree import Merkletree
from raiden.tests.utils.messages import (
    HASHLOCK_FOR_MERKLETREE,
    HASHLOCKS_SECRESTS,
    make_direct_transfer,
    make_lock,
)
from raiden.tests.utils.tester import new_nettingcontract
from raiden.transfer.state_change import Block
from raiden.utils import sha3, privatekey_to_address

# TODO:
# - change the hashroot and check older locks are not freed
# - add locked amounts and assert that they are respected


def increase_transferred_amount(from_channel, to_channel, amount):
    """ Helper to increase the transferred_amount of the channels without the
    need of creating/signing/register transfers.
    """
    from_channel.our_state.transferred_amount += amount
    to_channel.partner_state.transferred_amount += amount


def make_direct_transfer_from_channel(channel, partner_channel, amount, pkey):
    """ Helper to create and register a direct transfer from `channel` to
    `partner_channel`.
    """
    identifier = channel.our_state.nonce

    direct_transfer = channel.create_directtransfer(
        amount,
        identifier=identifier,
    )

    address = privatekey_to_address(pkey)
    sign_key = PrivateKey(pkey, ctx=GLOBAL_CTX, raw=True)
    direct_transfer.sign(sign_key, address)

    # if this fails it's not the right key for the current `channel`
    assert direct_transfer.sender == channel.our_state.address

    channel.register_transfer(direct_transfer)
    partner_channel.register_transfer(direct_transfer)

    return direct_transfer


def make_mediated_transfer(
        channel,
        partner_channel,
        initiator,
        target,
        lock,
        pkey,
        block_number,
        secret=None):
    """ Helper to create and register a mediated transfer from `channel` to
    `partner_channel`.
    """
    identifier = channel.our_state.nonce
    fee = 0

    mediated_transfer = channel.create_mediatedtransfer(
        initiator,
        target,
        fee,
        lock.amount,
        identifier,
        lock.expiration,
        lock.hashlock,
    )

    address = privatekey_to_address(pkey)
    sign_key = PrivateKey(pkey, ctx=GLOBAL_CTX, raw=True)
    mediated_transfer.sign(sign_key, address)

    channel.block_number = block_number
    partner_channel.block_number = block_number

    # if this fails it's not the right key for the current `channel`
    assert mediated_transfer.sender == channel.our_state.address

    channel.register_transfer(mediated_transfer)
    partner_channel.register_transfer(mediated_transfer)

    if secret is not None:
        channel.register_secret(secret)
        partner_channel.register_secret(secret)

    return mediated_transfer


@pytest.mark.parametrize('number_of_nodes', [2])
def test_new_channel(private_keys, tester_state, tester_channelmanager):
    """ Tests the state of a newly created netting channel. """
    pkey0, pkey1 = private_keys

    events = list()
    settle_timeout = 10
    channel = new_nettingcontract(
        pkey0,
        pkey1,
        tester_state,
        events.append,
        tester_channelmanager,
        settle_timeout,
    )

    assert channel.settleTimeout(sender=pkey0) == settle_timeout
    assert channel.tokenAddress(sender=pkey0) == tester_channelmanager.tokenAddress(sender=pkey0)
    assert channel.opened(sender=pkey0) == 0
    assert channel.closed(sender=pkey0) == 0
    assert channel.settled(sender=pkey0) == 0

    address_and_balances = channel.addressAndBalance(sender=pkey0)
    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    assert address_and_balances[0] == encode_hex(address0)
    assert address_and_balances[1] == 0
    assert address_and_balances[2] == encode_hex(address1)
    assert address_and_balances[3] == 0


def test_deposit(private_keys, tester_channelmanager, tester_state, tester_token):
    """ A call to deposit must increase the available token amount in the
    netting channel.
    """
    pkey0 = private_keys[0]
    pkey1 = private_keys[1]
    address0 = encode_hex(privatekey_to_address(pkey0))
    address1 = encode_hex(privatekey_to_address(pkey1))

    settle_timeout = 10
    events = list()

    # not using the tester_nettingcontracts fixture because it has a set balance
    channel = new_nettingcontract(
        pkey0,
        pkey1,
        tester_state,
        events.append,
        tester_channelmanager,
        settle_timeout,
    )

    deposit = 100

    # cannot deposit without approving
    assert channel.deposit(deposit, sender=pkey0) is False

    assert tester_token.approve(channel.address, deposit, sender=pkey0) is True

    # cannot deposit negative values
    with pytest.raises(abi.ValueOutOfBounds):
        channel.deposit(-1, sender=pkey0)

    zero_state = (address0, 0, address1, 0)
    assert tuple(channel.addressAndBalance(sender=pkey0)) == zero_state

    assert channel.deposit(deposit, sender=pkey0) is True

    deposit_state = (address0, deposit, address1, 0)
    assert tuple(channel.addressAndBalance(sender=pkey0)) == deposit_state
    assert tester_token.balanceOf(channel.address, sender=pkey0) == deposit

    # cannot over deposit (the allowance is depleted)
    assert channel.deposit(deposit, sender=pkey0) is False

    assert tester_token.approve(channel.address, deposit, sender=pkey0) is True
    assert channel.deposit(deposit, sender=pkey0) is True

    second_deposit_state = (address0, deposit * 2, address1, 0)
    assert tuple(channel.addressAndBalance(sender=pkey0)) == second_deposit_state


def test_deposit_events(
        private_keys,
        settle_timeout,
        tester_state,
        tester_channelmanager,
        tester_token,
        tester_events):

    """ A deposit must emit the events Transfer and a ChannelNewBalance. """
    private_key = private_keys[0]
    address = privatekey_to_address(private_key)

    nettingchannel = new_nettingcontract(
        private_key,
        private_keys[1],
        tester_state,
        tester_events.append,
        tester_channelmanager,
        settle_timeout,
    )

    initial_balance0 = tester_token.balanceOf(address, sender=private_key)
    deposit_amount = initial_balance0 // 10

    assert tester_token.approve(nettingchannel.address, deposit_amount, sender=private_key) is True
    assert nettingchannel.deposit(deposit_amount, sender=private_key) is True

    transfer_event = tester_events[-2]
    newbalance_event = tester_events[-1]

    assert transfer_event == {
        '_event_type': 'Transfer',
        '_from': encode_hex(address),
        '_to': nettingchannel.address,
        '_value': deposit_amount,
    }

    block_number = tester_state.block.number
    assert newbalance_event == {
        '_event_type': 'ChannelNewBalance',
        'token_address': encode_hex(tester_token.address),
        'participant': encode_hex(address),
        'balance': deposit_amount,
        'block_number': block_number,
    }


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


def test_settle_event(settle_timeout, tester_state, tester_events, tester_nettingcontracts):
    """ The event ChannelSettled is emitted when the channel is settled. """
    pkey0, _, nettingchannel = tester_nettingcontracts[0]

    nettingchannel.close('', sender=pkey0)

    tester_state.mine(number_of_blocks=settle_timeout + 1)

    previous_events = list(tester_events)
    nettingchannel.settle(sender=pkey0)

    # settle + a transfer per participant
    assert len(previous_events) + 3 == len(tester_events)

    block_number = tester_state.block.number
    settle_event = tester_events[-1]
    assert settle_event == {
        '_event_type': 'ChannelSettled',
        'block_number': block_number,
    }


def test_transfer_update_event(tester_state, tester_channels, tester_events):
    """ The event TransferUpdated is emitted after a successful call to
    updateTransfer.
    """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]
    address1 = privatekey_to_address(pkey1)

    direct0 = make_direct_transfer_from_channel(channel0, channel1, amount=90, pkey=pkey0)
    direct0_data = str(direct0.packed().data)

    nettingchannel.close('', sender=pkey0)

    previous_events = list(tester_events)
    nettingchannel.updateTransfer(direct0_data, sender=pkey1)
    assert len(previous_events) + 1 == len(tester_events)

    assert tester_events[-1] == {
        '_event_type': 'TransferUpdated',
        'node_address': address1.encode('hex'),
        'block_number': tester_state.block.number,
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
    nonparticipant_sign_key = PrivateKey(nonparticipant_key, ctx=GLOBAL_CTX, raw=True)

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
    sign_key = PrivateKey(pkey0, ctx=GLOBAL_CTX, raw=True)
    direct_transfer_other_token.sign(sign_key, address)

    direct_transfer_data = direct_transfer_other_token.encode()

    with pytest.raises(TransactionFailed):
        nettingchannel.close(direct_transfer_data, sender=pkey1)


def test_close_tampered_nonce(tester_state, tester_channels):
    """ Messages the nonce tampered must be rejected. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount=90, pkey=pkey0)
    transfer0_data = transfer0.encode()

    tampered_transfer = DirectTransfer.decode(transfer0_data)
    tampered_transfer.identifier += 1
    tampered_transfer_data = tampered_transfer.encode()

    with pytest.raises(TransactionFailed):
        nettingchannel.close(tampered_transfer_data, sender=pkey1)


def test_update_fails_on_open_channel(tester_channels):
    """ Cannot call updateTransfer on a open channel. """
    pkey0, _, nettingchannel, channel0, channel1 = tester_channels[0]

    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount=10, pkey=pkey0)
    transfer0_data = str(transfer0.packed().data)

    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(transfer0_data, sender=pkey0)


def test_update_not_allowed_after_settlement_period(settle_timeout, tester_channels, tester_state):
    """ updateTransfer cannot be called after the settlement period. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    direct0 = make_direct_transfer_from_channel(channel0, channel1, amount=70, pkey=pkey0)
    direct0_data = str(direct0.packed().data)

    nettingchannel.close('', sender=pkey0)
    tester_state.mine(number_of_blocks=settle_timeout + 1)

    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(direct0_data, sender=pkey1)


def test_update_not_allowed_for_the_closing_address(tester_channels):
    """ Closing address cannot call updateTransfer. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount=10, pkey=pkey0)
    transfer0_data = str(transfer0.packed().data)

    transfer1 = make_direct_transfer_from_channel(channel1, channel0, amount=10, pkey=pkey1)
    transfer1_data = str(transfer1.packed().data)

    nettingchannel.close('', sender=pkey0)

    # do not accept a transfer from the party that closed
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(transfer0_data, sender=pkey0)

    # nor a transfer from the partner
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(transfer1_data, sender=pkey0)


@pytest.mark.parametrize('number_of_nodes', [3])
def test_update_must_fail_with_a_nonparticipant_transfer(tester_channels, private_keys):
    """ updateTransfer must not accept a transfer from a non participant. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]
    nonparticipant_key = private_keys[2]

    # make a transfer where pkey1 is the target
    transfer_nonparticipant = DirectTransfer(
        identifier=1,
        nonce=1,
        token=channel0.token_address,
        transferred_amount=10,
        recipient=channel1.our_address,
        locksroot='',
    )

    nonparticipant_address = privatekey_to_address(nonparticipant_key)
    nonparticipant_sign_key = PrivateKey(nonparticipant_key, ctx=GLOBAL_CTX, raw=True)

    transfer_nonparticipant.sign(nonparticipant_sign_key, nonparticipant_address)
    transfer_nonparticipant_data = str(transfer_nonparticipant.packed().data)

    nettingchannel.close('', sender=pkey0)

    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(transfer_nonparticipant_data, sender=pkey1)


def test_update_called_multiple_times_same_transfer(tester_channels):
    """ updateTransfer can be called only once. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount=10, pkey=pkey0)
    transfer0_data = str(transfer0.packed().data)

    nettingchannel.close('', sender=pkey0)
    nettingchannel.updateTransfer(transfer0_data, sender=pkey1)

    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(transfer0_data, sender=pkey1)


def test_update_called_multiple_times_new_transfer(tester_channels):
    """ updateTransfer second call must fail even if there is a new transfer. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount=10, pkey=pkey0)
    transfer0_data = str(transfer0.packed().data)

    transfer1 = make_direct_transfer_from_channel(channel0, channel1, amount=10, pkey=pkey0)
    transfer1_data = str(transfer1.packed().data)

    nettingchannel.close('', sender=pkey0)
    nettingchannel.updateTransfer(transfer0_data, sender=pkey1)

    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(transfer1_data, sender=pkey1)


def test_update_called_multiple_times_older_transfer(tester_channels):
    """ updateTransfer second call must fail even if called with an older transfer. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount=10, pkey=pkey0)
    transfer0_data = str(transfer0.packed().data)

    transfer1 = make_direct_transfer_from_channel(channel0, channel1, amount=10, pkey=pkey0)
    transfer1_data = str(transfer1.packed().data)

    nettingchannel.close('', sender=pkey0)
    nettingchannel.updateTransfer(transfer1_data, sender=pkey1)

    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(transfer0_data, sender=pkey1)


def test_settle_unused_channel(
        deposit,
        settle_timeout,
        tester_state,
        tester_nettingcontracts,
        tester_token):

    """ Test settle of a channel with no transfers. """

    pkey0, pkey1, nettingchannel = tester_nettingcontracts[0]
    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    nettingchannel.close('', sender=pkey0)
    tester_state.mine(number_of_blocks=settle_timeout + 1)

    nettingchannel.settle(sender=pkey0)

    assert tester_token.balanceOf(address0, sender=pkey0) == initial_balance0 + deposit
    assert tester_token.balanceOf(address1, sender=pkey0) == initial_balance1 + deposit
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0


def test_settle_single_direct_transfer_for_closing_party(
        deposit,
        settle_timeout,
        tester_channels,
        tester_state,
        tester_token):

    """ Test settle of a channel with one direct transfer to the participant
    that called close.
    """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial0 = tester_token.balanceOf(address0, sender=pkey0)
    initial1 = tester_token.balanceOf(address1, sender=pkey0)

    amount = 90
    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount, pkey0)
    transfer0_data = str(transfer0.packed().data)

    nettingchannel.close(transfer0_data, sender=pkey1)

    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    assert tester_token.balanceOf(address0, sender=pkey0) == initial0 + deposit - amount
    assert tester_token.balanceOf(address1, sender=pkey0) == initial1 + deposit + amount
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0


def test_settle_single_direct_transfer_for_counterparty(
        deposit,
        settle_timeout,
        tester_channels,
        tester_state,
        tester_token):

    """ Test settle of a channel with one direct transfer to the participant
    that did not call close.
    """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial0 = tester_token.balanceOf(address0, sender=pkey0)
    initial1 = tester_token.balanceOf(address1, sender=pkey0)

    amount = 90
    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount, pkey0)
    transfer0_data = str(transfer0.packed().data)

    nettingchannel.close('', sender=pkey0)
    nettingchannel.updateTransfer(transfer0_data, sender=pkey1)

    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    assert tester_token.balanceOf(address0, sender=pkey0) == initial0 + deposit - amount
    assert tester_token.balanceOf(address1, sender=pkey0) == initial1 + deposit + amount
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0


def test_settle_two_direct_transfers(
        deposit,
        settle_timeout,
        tester_state,
        tester_channels,
        tester_token):

    """ Test settle of a channel with two direct transfers. """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    amount0 = 10
    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount0, pkey0)
    transfer0_data = str(transfer0.packed().data)

    amount1 = 30
    transfer1 = make_direct_transfer_from_channel(channel1, channel0, amount1, pkey1)
    transfer1_data = str(transfer1.packed().data)

    nettingchannel.close(transfer1_data, sender=pkey0)
    nettingchannel.updateTransfer(transfer0_data, sender=pkey1)

    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    balance0 = tester_token.balanceOf(address0, sender=pkey0)
    balance1 = tester_token.balanceOf(address1, sender=pkey0)
    assert balance0 == initial_balance0 + deposit - amount0 + amount1
    assert balance1 == initial_balance1 + deposit + amount0 - amount1
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0


@pytest.mark.parametrize('both_participants_deposit', [False])
@pytest.mark.parametrize('deposit', [100])
def test_settle_with_locked_mediated_transfer_for_counterparty(
        deposit,
        settle_timeout,
        reveal_timeout,
        tester_state,
        tester_channels,
        tester_token):

    """ Test settle with a locked mediated transfer for the counter party. """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]
    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial0 = tester_token.balanceOf(address0, sender=pkey0)
    initial1 = tester_token.balanceOf(address1, sender=pkey0)

    transferred_amount0 = 30
    increase_transferred_amount(channel0, channel1, transferred_amount0)

    expiration0 = tester_state.block.number + reveal_timeout + 5
    new_block = Block(tester_state.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)
    lock0 = Lock(amount=29, expiration=expiration0, hashlock=sha3('lock1'))
    mediated = make_mediated_transfer(
        channel0,
        channel1,
        address0,
        address1,
        lock0,
        pkey0,
        tester_state.block.number,
    )

    nettingchannel.close('', sender=pkey0)

    transfer_data = str(mediated.packed().data)
    nettingchannel.updateTransfer(transfer_data, sender=pkey1)

    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey1)

    # the balances only change by transferred_amount because the lock was /not/ unlocked
    balance0 = initial0 + deposit - transferred_amount0
    balance1 = initial1 + transferred_amount0

    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey0) == balance1


@pytest.mark.parametrize('both_participants_deposit', [False])
@pytest.mark.parametrize('deposit', [100])
def test_settle_with_locked_mediated_transfer_for_closing_party(
        deposit,
        settle_timeout,
        reveal_timeout,
        tester_state,
        tester_channels,
        tester_token):

    """ Test settle with a locked mediated transfer for the closing address. """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]
    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial0 = tester_token.balanceOf(address0, sender=pkey0)
    initial1 = tester_token.balanceOf(address1, sender=pkey0)

    transferred_amount0 = 30
    increase_transferred_amount(channel0, channel1, transferred_amount0)

    expiration0 = tester_state.block.number + reveal_timeout + 5
    new_block = Block(tester_state.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)
    lock0 = Lock(amount=29, expiration=expiration0, hashlock=sha3('lock1'))
    mediated = make_mediated_transfer(
        channel0,
        channel1,
        address0,
        address1,
        lock0,
        pkey0,
        tester_state.block.number,
    )

    transfer_data = str(mediated.packed().data)
    nettingchannel.close(transfer_data, sender=pkey1)

    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey1)

    # the balances only change by transferred_amount because the lock was /not/ unlocked
    balance0 = initial0 + deposit - transferred_amount0
    balance1 = initial1 + transferred_amount0

    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey0) == balance1


def test_settle_two_locked_mediated_transfer_messages(
        deposit,
        settle_timeout,
        reveal_timeout,
        tester_state,
        tester_channels,
        tester_token):

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]
    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey1)

    transferred_amount0 = 30
    increase_transferred_amount(channel0, channel1, transferred_amount0)

    transferred_amount1 = 70
    increase_transferred_amount(channel1, channel0, transferred_amount1)

    expiration0 = tester_state.block.number + reveal_timeout + 5
    new_block = Block(tester_state.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)
    lock0 = Lock(amount=29, expiration=expiration0, hashlock=sha3('lock1'))
    mediated0 = make_mediated_transfer(
        channel0,
        channel1,
        address0,
        address1,
        lock0,
        pkey0,
        tester_state.block.number,
    )
    mediated0_data = str(mediated0.packed().data)

    lock_expiration1 = tester_state.block.number + reveal_timeout + 5
    lock1 = Lock(amount=31, expiration=lock_expiration1, hashlock=sha3('lock2'))
    mediated1 = make_mediated_transfer(
        channel1,
        channel0,
        address1,
        address0,
        lock1,
        pkey1,
        tester_state.block.number,
    )
    mediated1_data = str(mediated1.packed().data)

    nettingchannel.close(mediated0_data, sender=pkey1)
    nettingchannel.updateTransfer(mediated1_data, sender=pkey0)

    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    # the balances only change by transferred_amount because the lock was /not/ unlocked
    balance0 = initial_balance0 + deposit - transferred_amount0 + transferred_amount1
    balance1 = initial_balance1 + deposit + transferred_amount0 - transferred_amount1

    assert tester_token.balanceOf(nettingchannel.address, sender=pkey1) == 0
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey1) == balance1


def test_two_direct_transfers(
        settle_timeout,
        deposit,
        tester_state,
        tester_channels,
        tester_token):

    """ The value of both transfers must be account for. """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial0 = tester_token.balanceOf(address0, sender=pkey0)
    initial1 = tester_token.balanceOf(address1, sender=pkey0)

    first_amount0 = 90
    make_direct_transfer_from_channel(channel0, channel1, first_amount0, pkey0)

    second_amount0 = 90
    second_direct0 = make_direct_transfer_from_channel(channel0, channel1, second_amount0, pkey0)
    second_direct0_data = str(second_direct0.packed().data)

    nettingchannel.close('', sender=pkey0)
    nettingchannel.updateTransfer(second_direct0_data, sender=pkey1)

    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    balance0 = initial0 + deposit - first_amount0 - second_amount0
    balance1 = initial1 + deposit + first_amount0 + second_amount0
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey0) == balance1
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0


def test_mediated_after_direct_transfer(
        reveal_timeout,
        settle_timeout,
        deposit,
        tester_state,
        tester_channels,
        tester_token):

    """ The transfer types must not change the behavior of the dispute. """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    first_amount0 = 90
    make_direct_transfer_from_channel(channel0, channel1, first_amount0, pkey0)

    lock_expiration = tester_state.block.number + reveal_timeout + 5
    new_block = Block(tester_state.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)
    lock1 = Lock(amount=31, expiration=lock_expiration, hashlock=sha3('lock2'))
    second_mediated0 = make_mediated_transfer(
        channel0,
        channel1,
        address0,
        address1,
        lock1,
        pkey0,
        tester_state.block.number,
    )
    second_mediated0_data = str(second_mediated0.packed().data)

    nettingchannel.close('', sender=pkey0)
    nettingchannel.updateTransfer(second_mediated0_data, sender=pkey1)

    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    # the balances only change by transferred_amount because the lock was /not/ unlocked
    balance0 = initial_balance0 + deposit - first_amount0
    balance1 = initial_balance1 + deposit + first_amount0

    assert tester_token.balanceOf(nettingchannel.address, sender=pkey1) == 0
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey1) == balance1


def test_withdraw(
        deposit,
        settle_timeout,
        reveal_timeout,
        tester_channels,
        tester_state,
        tester_token):

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    lock_amount = 31
    lock_expiration = tester_state.block.number + reveal_timeout + 5
    secret = 'secretsecretsecretsecretsecretse'
    hashlock = sha3(secret)
    new_block = Block(tester_state.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)
    lock0 = Lock(lock_amount, lock_expiration, hashlock)

    mediated0 = make_mediated_transfer(
        channel0,
        channel1,
        address0,
        address1,
        lock0,
        pkey0,
        tester_state.block.number,
        secret,
    )
    mediated0_data = str(mediated0.packed().data)

    proof = channel1.our_state.balance_proof.compute_proof_for_lock(
        secret,
        mediated0.lock,
    )

    nettingchannel.close(mediated0_data, sender=pkey1)

    tester_state.mine(number_of_blocks=1)

    nettingchannel.withdraw(
        proof.lock_encoded,
        ''.join(proof.merkle_proof),
        proof.secret,
        sender=pkey1,
    )

    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    balance0 = initial_balance0 + deposit - lock0.amount
    balance1 = initial_balance1 + deposit + lock0.amount
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey0) == balance1
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0


# This test must not use tester_channels since these proxies do automatic
# mining
def test_withdraw_at_settlement_block(
        deposit,
        settle_timeout,
        tester_nettingcontracts,
        tester_state,
        tester_token):

    """ It must be possible to unlock a lock up to and including the settlment
    block.
    """

    pkey0, pkey1, nettingchannel = tester_nettingcontracts[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    lock_amount = 31
    lock_expiration = tester_state.block.number + settle_timeout
    secret = 'settlementsettlementsettlementse'
    hashlock = sha3(secret)

    lock0 = Lock(
        amount=lock_amount,
        expiration=lock_expiration,
        hashlock=hashlock,
    )
    lock0_bytes = bytes(lock0.as_bytes)
    lock0_hash = sha3(lock0_bytes)

    opened_block = nettingchannel.opened(sender=pkey0)
    nonce = 1 + (opened_block * (2 ** 32))

    mediated0 = MediatedTransfer(
        identifier=1,
        nonce=nonce,
        token=tester_token.address,
        transferred_amount=0,
        recipient=address1,
        locksroot=lock0_hash,
        lock=lock0,
        target=address1,
        initiator=address0,
        fee=0,
    )

    sign_key0 = PrivateKey(pkey0, ctx=GLOBAL_CTX, raw=True)
    mediated0.sign(sign_key0, address0)
    mediated0_data = str(mediated0.packed().data)
    nettingchannel.close(mediated0_data, sender=pkey1)

    block_until_settlement_end = lock_expiration - tester_state.block.number
    tester_state.mine(number_of_blocks=block_until_settlement_end)

    assert lock_expiration == tester_state.block.number
    nettingchannel.withdraw(
        lock0_bytes,
        '',  # the lock itself it the root, the proof is empty
        secret,
        sender=pkey1,
    )

    tester_state.mine(number_of_blocks=1)
    nettingchannel.settle(sender=pkey0)

    balance0 = initial_balance0 + deposit - lock0.amount
    balance1 = initial_balance1 + deposit + lock0.amount
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey0) == balance1
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0


def test_withdraw_expired_lock(reveal_timeout, tester_channels, tester_state):
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    lock_timeout = reveal_timeout + 5
    lock_expiration = tester_state.block.number + lock_timeout
    secret = 'expiredlockexpiredlockexpiredloc'
    hashlock = sha3(secret)
    new_block = Block(tester_state.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)
    lock1 = Lock(amount=31, expiration=lock_expiration, hashlock=hashlock)

    mediated0 = make_mediated_transfer(
        channel1,
        channel0,
        privatekey_to_address(pkey0),
        privatekey_to_address(pkey1),
        lock1,
        pkey1,
        tester_state.block.number,
        secret,
    )
    mediated0_data = str(mediated0.packed().data)

    nettingchannel.close(mediated0_data, sender=pkey0)

    # expire the lock
    tester_state.mine(number_of_blocks=lock_timeout + 1)

    unlock_proofs = list(channel0.our_state.balance_proof.get_known_unlocks())
    proof = unlock_proofs[0]

    with pytest.raises(TransactionFailed):
        nettingchannel.withdraw(
            proof.lock_encoded,
            ''.join(proof.merkle_proof),
            proof.secret,
            sender=pkey0,
        )


@pytest.mark.parametrize('settle_timeout', [50])
@pytest.mark.parametrize('reveal_timeout', [5])
def test_withdraw_both_participants(
        deposit,
        settle_timeout,
        reveal_timeout,
        tester_channels,
        tester_state,
        tester_token):

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    secret = 'secretsecretsecretsecretsecretse'
    hashlock = sha3(secret)

    lock_amount = 31
    lock01_expiration = tester_state.block.number + settle_timeout - 1 * reveal_timeout
    lock10_expiration = tester_state.block.number + settle_timeout - 2 * reveal_timeout

    new_block = Block(tester_state.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)

    # using the same hashlock and amount is intentional
    lock01 = Lock(lock_amount, lock01_expiration, hashlock)
    lock10 = Lock(lock_amount, lock10_expiration, hashlock)

    mediated01 = make_mediated_transfer(
        channel0,
        channel1,
        address0,
        address1,
        lock01,
        pkey0,
        tester_state.block.number,
        secret,
    )
    mediated01_data = str(mediated01.packed().data)

    mediated10 = make_mediated_transfer(
        channel1,
        channel0,
        address1,
        address0,
        lock10,
        pkey1,
        tester_state.block.number,
        secret,
    )
    mediated10_data = str(mediated10.packed().data)

    nettingchannel.close(mediated01_data, sender=pkey1)
    tester_state.mine(number_of_blocks=1)

    nettingchannel.updateTransfer(mediated10_data, sender=pkey0)
    tester_state.mine(number_of_blocks=1)

    proof01 = channel1.our_state.balance_proof.compute_proof_for_lock(
        secret,
        mediated01.lock,
    )
    nettingchannel.withdraw(
        proof01.lock_encoded,
        ''.join(proof01.merkle_proof),
        proof01.secret,
        sender=pkey1,
    )

    proof10 = channel0.our_state.balance_proof.compute_proof_for_lock(
        secret,
        mediated10.lock,
    )
    nettingchannel.withdraw(
        proof10.lock_encoded,
        ''.join(proof10.merkle_proof),
        proof10.secret,
        sender=pkey0,
    )

    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    balance0 = initial_balance0 + deposit - lock01.amount + lock10.amount
    balance1 = initial_balance1 + deposit + lock01.amount - lock10.amount
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey0) == balance1
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0


def test_withdraw_twice(reveal_timeout, tester_channels, tester_state):
    """ A lock can be withdrawn only once, the second try must fail. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    lock_expiration = tester_state.block.number + reveal_timeout + 5
    secret = 'secretsecretsecretsecretsecretse'
    new_block = Block(tester_state.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)
    lock = Lock(17, lock_expiration, sha3(secret))

    mediated0 = make_mediated_transfer(
        channel1,
        channel0,
        privatekey_to_address(pkey1),
        privatekey_to_address(pkey0),
        lock,
        pkey1,
        tester_state.block.number,
        secret,
    )
    mediated0_data = str(mediated0.packed().data)

    nettingchannel.close(mediated0_data, sender=pkey0)

    unlock_proofs = list(channel0.our_state.balance_proof.get_known_unlocks())
    proof = unlock_proofs[0]

    nettingchannel.withdraw(
        proof.lock_encoded,
        ''.join(proof.merkle_proof),
        proof.secret,
        sender=pkey0,
    )

    with pytest.raises(TransactionFailed):
        nettingchannel.withdraw(
            proof.lock_encoded,
            ''.join(proof.merkle_proof),
            proof.secret,
            sender=pkey0,
        )


@pytest.mark.parametrize('tree', HASHLOCK_FOR_MERKLETREE)
def test_withdraw_fails_with_partial_merkle_proof(
        tree,
        tester_channels,
        tester_state,
        settle_timeout):

    """ withdraw must fail if informed proof is not complete. """
    pkey0, pkey1, nettingchannel, _, _ = tester_channels[0]

    current_block = tester_state.block.number
    expiration = current_block + settle_timeout - 1
    locks = [
        make_lock(
            hashlock=hashlock,
            expiration=expiration,
        )
        for hashlock in tree
    ]

    merkle_tree = Merkletree(sha3(lock.as_bytes) for lock in locks)

    opened_block = nettingchannel.opened(sender=pkey0)
    nonce = 1 + (opened_block * (2 ** 32))
    direct_transfer = make_direct_transfer(
        nonce=nonce,
        locksroot=merkle_tree.merkleroot,
    )

    address = privatekey_to_address(pkey0)
    sign_key = PrivateKey(pkey0, ctx=GLOBAL_CTX, raw=True)
    direct_transfer.sign(sign_key, address)

    direct_transfer_data = str(direct_transfer.packed().data)
    nettingchannel.close(direct_transfer_data, sender=pkey1)

    for lock in locks:
        secret = HASHLOCKS_SECRESTS[lock.hashlock]
        lock_encoded = lock.as_bytes
        merkle_proof = merkle_tree.make_proof(sha3(lock_encoded))

        # withdraw must fail regardless of which part of the proof is removed
        for hash_ in merkle_proof:
            tampered_proof = list(merkle_proof)
            tampered_proof.remove(hash_)

            with pytest.raises(TransactionFailed):
                nettingchannel.withdraw(
                    lock_encoded,
                    ''.join(tampered_proof),
                    secret,
                    sender=pkey1,
                )


@pytest.mark.parametrize('tree', HASHLOCK_FOR_MERKLETREE)
def test_withdraw_tampered_merkle_proof(tree, tester_channels, tester_state, settle_timeout):
    """ withdraw must fail if the proof is tampered. """
    pkey0, pkey1, nettingchannel, _, _ = tester_channels[0]

    current_block = tester_state.block.number
    expiration = current_block + settle_timeout - 1
    locks = [
        make_lock(
            hashlock=hashlock,
            expiration=expiration,
        )
        for hashlock in tree
    ]

    merkle_tree = Merkletree(sha3(lock.as_bytes) for lock in locks)

    opened_block = nettingchannel.opened(sender=pkey0)
    nonce = 1 + (opened_block * (2 ** 32))
    direct_transfer = make_direct_transfer(
        nonce=nonce,
        locksroot=merkle_tree.merkleroot,
    )

    address = privatekey_to_address(pkey0)
    sign_key = PrivateKey(pkey0, ctx=GLOBAL_CTX, raw=True)
    direct_transfer.sign(sign_key, address)

    direct_transfer_data = str(direct_transfer.packed().data)
    nettingchannel.close(direct_transfer_data, sender=pkey1)

    for lock in locks:
        secret = HASHLOCKS_SECRESTS[lock.hashlock]

        lock_encoded = lock.as_bytes
        merkle_proof = merkle_tree.make_proof(sha3(lock_encoded))

        # withdraw must fail regardless of which part of the proof is tampered
        for pos, hash_ in enumerate(merkle_proof):
            # changing arbitrary bytes from the proof
            tampered_hash = bytearray(hash_)
            tampered_hash[5], tampered_hash[6] = tampered_hash[6], tampered_hash[5]

            tampered_proof = list(merkle_proof)
            tampered_proof[pos] = str(tampered_hash)

            with pytest.raises(TransactionFailed):
                nettingchannel.withdraw(
                    lock_encoded,
                    ''.join(tampered_proof),
                    secret,
                    sender=pkey1,
                )


@pytest.mark.parametrize('tree', HASHLOCK_FOR_MERKLETREE)
def test_withdraw_tampered_lock_amount(
        tree,
        tester_channels,
        tester_state,
        tester_token,
        settle_timeout):

    """ withdraw must fail if the lock amonut is tampered. """
    pkey0, pkey1, nettingchannel, _, _ = tester_channels[0]

    current_block = tester_state.block.number
    expiration = current_block + settle_timeout - 1
    locks = [
        make_lock(
            hashlock=hashlock,
            expiration=expiration,
        )
        for hashlock in tree
    ]

    merkle_tree = Merkletree(sha3(lock.as_bytes) for lock in locks)

    opened_block = nettingchannel.opened(sender=pkey0)
    nonce = 1 + (opened_block * (2 ** 32))
    direct_transfer = make_direct_transfer(
        nonce=nonce,
        locksroot=merkle_tree.merkleroot,
        token=tester_token.address,
    )

    address = privatekey_to_address(pkey0)
    sign_key = PrivateKey(pkey0, ctx=GLOBAL_CTX, raw=True)
    direct_transfer.sign(sign_key, address)

    direct_transfer_data = str(direct_transfer.packed().data)
    nettingchannel.close(direct_transfer_data, sender=pkey1)

    for lock in locks:
        secret = HASHLOCKS_SECRESTS[lock.hashlock]

        lock_encoded = lock.as_bytes
        merkle_proof = merkle_tree.make_proof(sha3(lock_encoded))

        tampered_lock = make_lock(
            amount=lock.amount * 100,
            hashlock=lock.hashlock,
            expiration=lock.expiration,
        )
        tampered_lock_encoded = sha3(tampered_lock.as_bytes)

        with pytest.raises(TransactionFailed):
            nettingchannel.withdraw(
                tampered_lock_encoded,
                ''.join(merkle_proof),
                secret,
                sender=pkey1,
            )


def test_settlement_with_unauthorized_token_transfer(
        deposit,
        settle_timeout,
        tester_state,
        tester_channels,
        tester_token):

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    amount0 = 10
    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount0, pkey0)
    transfer0_data = str(transfer0.packed().data)

    amount1 = 30
    transfer1 = make_direct_transfer_from_channel(channel1, channel0, amount1, pkey1)
    transfer1_data = str(transfer1.packed().data)

    extra_amount = 10
    assert tester_token.transfer(nettingchannel.address, extra_amount, sender=pkey0)

    nettingchannel.close(transfer1_data, sender=pkey0)
    nettingchannel.updateTransfer(transfer0_data, sender=pkey1)

    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    balance0 = tester_token.balanceOf(address0, sender=pkey0)
    balance1 = tester_token.balanceOf(address1, sender=pkey0)

    # Make sure that the extra amount is burned/locked in the netting channel
    assert balance0 == initial_balance0 + deposit - amount0 + amount1 - extra_amount
    assert balance1 == initial_balance1 + deposit + amount0 - amount1
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey1) == extra_amount


def test_netting(deposit, settle_timeout, tester_channels, tester_state, tester_token):
    """ Transferred amount can be larger than the deposit. """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]
    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey1)

    transferred_amount0 = deposit * 3 + 30
    increase_transferred_amount(channel0, channel1, transferred_amount0)

    transferred_amount1 = deposit * 3 + 70
    increase_transferred_amount(channel1, channel0, transferred_amount1)

    amount0 = 10
    transferred_amount0 += amount0
    direct0 = make_direct_transfer_from_channel(channel0, channel1, amount0, pkey0)
    direct0_data = str(direct0.packed().data)

    amount1 = 30
    transferred_amount1 += amount1
    direct1 = make_direct_transfer_from_channel(channel1, channel0, amount1, pkey1)
    direct1_data = str(direct1.packed().data)

    nettingchannel.close(direct1_data, sender=pkey0)
    nettingchannel.updateTransfer(direct0_data, sender=pkey1)

    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    # the balances only change by transferred_amount because the lock was /not/ unlocked
    balance0 = initial_balance0 + deposit - transferred_amount0 + transferred_amount1
    balance1 = initial_balance1 + deposit + transferred_amount0 - transferred_amount1

    assert tester_token.balanceOf(nettingchannel.address, sender=pkey1) == 0
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey1) == balance1
