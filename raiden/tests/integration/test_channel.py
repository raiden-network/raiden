# -*- coding: utf8 -*-
from __future__ import division

from ethereum import tester

from raiden.channel import ChannelEndState, ChannelExternalState, Channel


def test_unlock(state, channel, token, events, asset_address, reveal_timeout,
                settle_timeout):
    block_alarm = list()
    original_mine = state.mine

    def wrap_mine(*args, **kwargs):
        original_mine(*args, **kwargs)

        block_number = get_block_number()
        for callback in block_alarm:
            callback(block_number)

    def register_block_alarm(callback):
        block_alarm.append(callback)

    def get_block_number():
        return len(state.blocks)

    state.mine = wrap_mine

    address0 = tester.a0
    address1 = tester.a1

    privatekey1 = tester.k1

    token0 = token
    token1 = tester.ABIContract(
        state,
        token.translator,
        token.address,
        default_key=privatekey1,
    )

    netting_channel0 = channel
    netting_channel1 = tester.ABIContract(
        state,
        channel.translator,
        channel.address,
        default_key=privatekey1,
    )

    # setup asset and open the channel
    half_balance = token0.balanceOf(address1) // 2
    token0.transfer(address1, half_balance)

    balance0 = token0.balanceOf(address0)
    token0.approve(netting_channel0.address, balance0)

    balance1 = token1.balanceOf(tester.a1)
    token1.approve(netting_channel1.address, balance1)

    netting_channel0.deposit(balance0)
    netting_channel1.deposit(balance1)

    # setup python's channels
    our_state0 = ChannelEndState(address0, balance0)
    partner_state0 = ChannelEndState(address1, balance1)
    channel_for_hashlock0 = list()
    external_state0 = ChannelExternalState(
        register_block_alarm,
        lambda *args: channel_for_hashlock0.append(args),
        get_block_number,
        netting_channel0,
    )
    channel0 = Channel(
        our_state0, partner_state0, external_state0,
        asset_address, reveal_timeout, settle_timeout,
    )

    our_state1 = ChannelEndState(address1, balance1)
    partner_state1 = ChannelEndState(address0, balance0)
    channel_for_hashlock1 = list()
    external_state1 = ChannelExternalState(
        register_block_alarm,
        lambda *args: channel_for_hashlock1.append(args),
        get_block_number,
        netting_channel1,
    )
    channel1 = Channel(
        our_state1, partner_state1, external_state1,
        asset_address, reveal_timeout, settle_timeout,
    )
