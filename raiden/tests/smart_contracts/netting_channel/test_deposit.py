# -*- coding: utf-8 -*-
from __future__ import division

import pytest
from ethereum import abi
from ethereum.utils import encode_hex

from raiden.tests.utils.tester import new_nettingcontract
from raiden.utils import privatekey_to_address


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
