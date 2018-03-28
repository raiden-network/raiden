# -*- coding: utf-8 -*-
import pytest

from raiden.api.python import RaidenAPI2
from raiden.tests.utils.blockchain import wait_until_block
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLED,
)


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_close_regression(raiden_network, token_addresses):
    """ The python api was using the wrong balance proof to close the channel,
    thus the close was failing if a transfer was made.
    """
    node1, node2 = raiden_network
    token_address = token_addresses[0]

    api1 = RaidenAPI2(node1.raiden)

    channel_list = api1.get_channel_list(token_address, node2.raiden.address)
    channel12 = channel_list[0]

    token_proxy = node1.raiden.chain.token(token_address)
    node1_balance_before = token_proxy.balance_of(api1.address)
    node2_balance_before = token_proxy.balance_of(node2.raiden.address)
    channel_balance = token_proxy.balance_of(channel12.identifier)

    amount = 10
    assert api1.transfer(token_address, amount, node2.raiden.address)

    api1.channel_close(token_address, node2.raiden.address)

    node1.raiden.poll_blockchain_events()
    assert channel12.state == CHANNEL_STATE_CLOSED

    settlement_block = (
        channel12.external_state.closed_block +
        channel12.settle_timeout +
        5  # arbitrary number of additional blocks, used to wait for the settle() call
    )
    wait_until_block(node1.raiden.chain, settlement_block)

    node1.raiden.poll_blockchain_events()
    assert channel12.state == CHANNEL_STATE_SETTLED

    node1_withdraw_amount = channel12.balance
    node2_withdraw_amount = channel_balance - node1_withdraw_amount

    node2_expected_balance = node2_balance_before + node2_withdraw_amount

    assert token_proxy.balance_of(api1.address) == node1_balance_before + node1_withdraw_amount
    assert token_proxy.balance_of(node2.raiden.address) == node2_expected_balance
