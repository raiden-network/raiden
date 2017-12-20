# -*- coding: utf-8 -*-
import pytest

from raiden.messages import Lock
from raiden.transfer.state_change import Block
from raiden.utils import sha3, privatekey_to_address, event_decoder
from raiden.tests.utils.transfer import (
    increase_transferred_amount,
    make_direct_transfer_from_channel,
    make_mediated_transfer,
)


def test_settle_event(settle_timeout, tester_chain, tester_events, tester_nettingcontracts):
    """ The event ChannelSettled is emitted when the channel is settled. """
    pkey0, _, nettingchannel = tester_nettingcontracts[0]

    nettingchannel.close(sender=pkey0)

    tester_chain.mine(number_of_blocks=settle_timeout + 1)

    previous_events = list(tester_events)
    tester_chain.head_state.log_listeners.append(tester_events.append)
    nettingchannel.settle(sender=pkey0)

    # settle + a transfer per participant
    assert len(previous_events) + 3 == len(tester_events)

    settle_event = event_decoder(tester_events[-1], nettingchannel.translator)
    assert settle_event == {
        '_event_type': b'ChannelSettled',
    }


def test_settle_unused_channel(
        deposit,
        settle_timeout,
        tester_chain,
        tester_nettingcontracts,
        tester_token):

    """ Test settle of a channel with no transfers. """

    pkey0, pkey1, nettingchannel = tester_nettingcontracts[0]
    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    nettingchannel.close(sender=pkey0)
    tester_chain.mine(number_of_blocks=settle_timeout + 1)

    nettingchannel.settle(sender=pkey0)

    assert tester_token.balanceOf(address0, sender=pkey0) == initial_balance0 + deposit
    assert tester_token.balanceOf(address1, sender=pkey0) == initial_balance1 + deposit
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0


def test_settle_single_direct_transfer_for_closing_party(
        deposit,
        settle_timeout,
        tester_channels,
        tester_chain,
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
    block_number = tester_chain.block.number
    transfer0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount,
        pkey0,
    )
    transfer0_hash = sha3(transfer0.packed().data[:-65])

    nettingchannel.close(
        transfer0.nonce,
        transfer0.transferred_amount,
        transfer0.locksroot,
        transfer0_hash,
        transfer0.signature,
        sender=pkey1,
    )

    tester_chain.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    assert tester_token.balanceOf(address0, sender=pkey0) == initial0 + deposit - amount
    assert tester_token.balanceOf(address1, sender=pkey0) == initial1 + deposit + amount
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0


def test_settle_single_direct_transfer_for_counterparty(
        deposit,
        settle_timeout,
        tester_channels,
        tester_chain,
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
    block_number = tester_chain.block.number
    transfer0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount,
        pkey0,
    )
    transfer0_hash = sha3(transfer0.packed().data[:-65])

    nettingchannel.close(sender=pkey0)
    nettingchannel.updateTransfer(
        transfer0.nonce,
        transfer0.transferred_amount,
        transfer0.locksroot,
        transfer0_hash,
        transfer0.signature,
        sender=pkey1,
    )

    tester_chain.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    assert tester_token.balanceOf(address0, sender=pkey0) == initial0 + deposit - amount
    assert tester_token.balanceOf(address1, sender=pkey0) == initial1 + deposit + amount
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0


def test_settle_two_direct_transfers(
        deposit,
        settle_timeout,
        tester_chain,
        tester_channels,
        tester_token):

    """ Test settle of a channel with two direct transfers. """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    amount0 = 10
    block_number = tester_chain.block.number
    transfer0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount0,
        pkey0,
    )

    amount1 = 30
    block_number = tester_chain.block.number
    transfer1 = make_direct_transfer_from_channel(
        block_number,
        channel1,
        channel0,
        amount1,
        pkey1,
    )
    transfer1_hash = sha3(transfer1.packed().data[:-65])

    nettingchannel.close(
        transfer1.nonce,
        transfer1.transferred_amount,
        transfer1.locksroot,
        transfer1_hash,
        transfer1.signature,
        sender=pkey0,
    )

    transfer0_hash = sha3(transfer0.packed().data[:-65])
    nettingchannel.updateTransfer(
        transfer0.nonce,
        transfer0.transferred_amount,
        transfer0.locksroot,
        transfer0_hash,
        transfer0.signature,
        sender=pkey1,
    )

    tester_chain.mine(number_of_blocks=settle_timeout + 1)
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
        tester_chain,
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

    expiration0 = tester_chain.block.number + reveal_timeout + 5
    new_block = Block(tester_chain.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)
    lock0 = Lock(amount=29, expiration=expiration0, hashlock=sha3(b'lock1'))
    mediated0 = make_mediated_transfer(
        channel0,
        channel1,
        address0,
        address1,
        lock0,
        pkey0,
        tester_chain.block.number,
    )

    nettingchannel.close(sender=pkey0)

    mediated0_hash = sha3(mediated0.packed().data[:-65])
    nettingchannel.updateTransfer(
        mediated0.nonce,
        mediated0.transferred_amount,
        mediated0.locksroot,
        mediated0_hash,
        mediated0.signature,
        sender=pkey1,
    )

    tester_chain.mine(number_of_blocks=settle_timeout + 1)
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
        tester_chain,
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

    expiration0 = tester_chain.block.number + reveal_timeout + 5
    new_block = Block(tester_chain.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)
    lock0 = Lock(amount=29, expiration=expiration0, hashlock=sha3(b'lock1'))
    mediated0 = make_mediated_transfer(
        channel0,
        channel1,
        address0,
        address1,
        lock0,
        pkey0,
        tester_chain.block.number,
    )

    mediated0_hash = sha3(mediated0.packed().data[:-65])
    nettingchannel.close(
        mediated0.nonce,
        mediated0.transferred_amount,
        mediated0.locksroot,
        mediated0_hash,
        mediated0.signature,
        sender=pkey1,
    )

    tester_chain.mine(number_of_blocks=settle_timeout + 1)
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
        tester_chain,
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

    expiration0 = tester_chain.block.number + reveal_timeout + 5
    new_block = Block(tester_chain.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)
    lock0 = Lock(amount=29, expiration=expiration0, hashlock=sha3(b'lock1'))
    mediated0 = make_mediated_transfer(
        channel0,
        channel1,
        address0,
        address1,
        lock0,
        pkey0,
        tester_chain.block.number,
    )

    lock_expiration1 = tester_chain.block.number + reveal_timeout + 5
    lock1 = Lock(amount=31, expiration=lock_expiration1, hashlock=sha3(b'lock2'))
    mediated1 = make_mediated_transfer(
        channel1,
        channel0,
        address1,
        address0,
        lock1,
        pkey1,
        tester_chain.block.number,
    )

    mediated0_hash = sha3(mediated0.packed().data[:-65])
    nettingchannel.close(
        mediated0.nonce,
        mediated0.transferred_amount,
        mediated0.locksroot,
        mediated0_hash,
        mediated0.signature,
        sender=pkey1,
    )

    mediated1_hash = sha3(mediated1.packed().data[:-65])
    nettingchannel.updateTransfer(
        mediated1.nonce,
        mediated1.transferred_amount,
        mediated1.locksroot,
        mediated1_hash,
        mediated1.signature,
        sender=pkey0,
    )

    tester_chain.mine(number_of_blocks=settle_timeout + 1)
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
        tester_chain,
        tester_channels,
        tester_token):

    """ The value of both transfers must be account for. """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial0 = tester_token.balanceOf(address0, sender=pkey0)
    initial1 = tester_token.balanceOf(address1, sender=pkey0)

    first_amount0 = 90
    block_number = tester_chain.block.number
    make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        first_amount0,
        pkey0,
    )

    second_amount0 = 90
    block_number = tester_chain.block.number
    second_direct0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        second_amount0,
        pkey0,
    )

    nettingchannel.close(sender=pkey0)

    second_direct0_hash = sha3(second_direct0.packed().data[:-65])
    nettingchannel.updateTransfer(
        second_direct0.nonce,
        second_direct0.transferred_amount,
        second_direct0.locksroot,
        second_direct0_hash,
        second_direct0.signature,
        sender=pkey1,
    )

    tester_chain.mine(number_of_blocks=settle_timeout + 1)
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
        tester_chain,
        tester_channels,
        tester_token):

    """ The transfer types must not change the behavior of the dispute. """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    first_amount0 = 90
    block_number = tester_chain.block.number
    make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        first_amount0,
        pkey0,
    )

    lock_expiration = tester_chain.block.number + reveal_timeout + 5
    new_block = Block(tester_chain.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)
    lock1 = Lock(amount=31, expiration=lock_expiration, hashlock=sha3(b'lock2'))
    second_mediated0 = make_mediated_transfer(
        channel0,
        channel1,
        address0,
        address1,
        lock1,
        pkey0,
        tester_chain.block.number,
    )

    nettingchannel.close(sender=pkey0)

    second_mediated0_hash = sha3(second_mediated0.packed().data[:-65])
    nettingchannel.updateTransfer(
        second_mediated0.nonce,
        second_mediated0.transferred_amount,
        second_mediated0.locksroot,
        second_mediated0_hash,
        second_mediated0.signature,
        sender=pkey1,
    )

    tester_chain.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    # the balances only change by transferred_amount because the lock was /not/ unlocked
    balance0 = initial_balance0 + deposit - first_amount0
    balance1 = initial_balance1 + deposit + first_amount0

    assert tester_token.balanceOf(nettingchannel.address, sender=pkey1) == 0
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey1) == balance1


def test_settlement_with_unauthorized_token_transfer(
        deposit,
        settle_timeout,
        tester_chain,
        tester_channels,
        tester_token):

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    amount0 = 10
    block_number = tester_chain.block.number
    transfer0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount0,
        pkey0,
    )

    amount1 = 30
    block_number = tester_chain.block.number
    transfer1 = make_direct_transfer_from_channel(
        block_number,
        channel1,
        channel0,
        amount1,
        pkey1,
    )

    extra_amount = 10
    assert tester_token.transfer(nettingchannel.address, extra_amount, sender=pkey0)

    transfer1_hash = sha3(transfer1.packed().data[:-65])
    nettingchannel.close(
        transfer1.nonce,
        transfer1.transferred_amount,
        transfer1.locksroot,
        transfer1_hash,
        transfer1.signature,
        sender=pkey0,
    )

    transfer0_hash = sha3(transfer0.packed().data[:-65])
    nettingchannel.updateTransfer(
        transfer0.nonce,
        transfer0.transferred_amount,
        transfer0.locksroot,
        transfer0_hash,
        transfer0.signature,
        sender=pkey1,
    )

    tester_chain.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    balance0 = tester_token.balanceOf(address0, sender=pkey0)
    balance1 = tester_token.balanceOf(address1, sender=pkey0)

    # Make sure that the extra amount is burned/locked in the netting channel
    assert balance0 == initial_balance0 + deposit - amount0 + amount1 - extra_amount
    assert balance1 == initial_balance1 + deposit + amount0 - amount1
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey1) == extra_amount


def test_netting(deposit, settle_timeout, tester_channels, tester_chain, tester_token):
    """ Transferred amount can be larger than the deposit. """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]
    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey1)

    # increase the transferred amount by three times the deposits
    for _ in range(3):
        increase_transferred_amount(channel0, channel1, deposit)
        increase_transferred_amount(channel1, channel0, deposit)

    transferred_amount0 = deposit * 3
    transferred_amount1 = deposit * 3

    amount0 = 10
    transferred_amount0 += amount0
    block_number = tester_chain.block.number
    direct0 = make_direct_transfer_from_channel(
        block_number,
        channel0,
        channel1,
        amount0,
        pkey0,
    )

    amount1 = 30
    transferred_amount1 += amount1
    block_number = tester_chain.block.number
    direct1 = make_direct_transfer_from_channel(
        block_number,
        channel1,
        channel0,
        amount1,
        pkey1,
    )

    direct1_hash = sha3(direct1.packed().data[:-65])
    nettingchannel.close(
        direct1.nonce,
        direct1.transferred_amount,
        direct1.locksroot,
        direct1_hash,
        direct1.signature,
        sender=pkey0,
    )

    direct0_hash = sha3(direct0.packed().data[:-65])
    nettingchannel.updateTransfer(
        direct0.nonce,
        direct0.transferred_amount,
        direct0.locksroot,
        direct0_hash,
        direct0.signature,
        sender=pkey1,
    )

    tester_chain.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    # the balances only change by transferred_amount because the lock was /not/ unlocked
    balance0 = initial_balance0 + deposit - transferred_amount0 + transferred_amount1
    balance1 = initial_balance1 + deposit + transferred_amount0 - transferred_amount1

    assert tester_token.balanceOf(nettingchannel.address, sender=pkey1) == 0
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey1) == balance1
