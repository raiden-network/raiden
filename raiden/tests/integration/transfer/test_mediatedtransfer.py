# -*- coding: utf-8 -*-
import pytest

from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import (
    assert_synched_channel_state,
    mediated_transfer,
)


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_mediated_transfer(raiden_network, deposit, token_addresses, network_wait):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]

    amount = 10
    mediated_transfer(
        app0,
        app2,
        token_address,
        amount,
        timeout=network_wait,
    )

    assert_synched_channel_state(
        token_address,
        app0, deposit - amount, [],
        app1, deposit + amount, [],
    )
    assert_synched_channel_state(
        token_address,
        app1, deposit - amount, [],
        app2, deposit + amount, [],
    )


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_mediated_transfer_with_entire_deposit(
        raiden_network,
        token_addresses,
        deposit,
        network_wait):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]

    mediated_transfer(
        app0,
        app2,
        token_address,
        deposit,
        timeout=network_wait,
    )

    mediated_transfer(
        app2,
        app0,
        token_address,
        deposit * 2,
        timeout=network_wait,
    )

    assert_synched_channel_state(
        token_address,
        app0, deposit * 2, [],
        app1, 0, [],
    )
    assert_synched_channel_state(
        token_address,
        app1, deposit * 2, [],
        app2, 0, [],
    )
