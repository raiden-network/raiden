# -*- coding: utf-8 -*-
import pytest
import gevent

from raiden.tests.utils.transfer import (
    direct_transfer,
    mediated_transfer,
    channel,
    get_sent_transfer,
)

from raiden.messages import DirectTransfer


@pytest.mark.parametrize('privatekey_seed', ['fullnetwork:{}'])
@pytest.mark.parametrize('channels_per_node', [2])
@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('deposit', [2 ** 20])
def test_fullnetwork(raiden_chain):
    app0, app1, app2, app3 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    token_address = app0.raiden.chain.default_registry.token_addresses()[0]
    channel_0_1 = channel(app0, app1, token_address)
    channel_1_2 = channel(app1, app2, token_address)
    channel_3_2 = channel(app3, app2, token_address)
    channel_0_3 = channel(app0, app3, token_address)

    amount = 80
    direct_transfer(app0, app1, token_address, amount)
    last_transfer = get_sent_transfer(channel_0_1, 0)
    assert last_transfer.transferred_amount == 80

    amount = 50
    direct_transfer(app1, app2, token_address, amount)
    last_transfer = get_sent_transfer(channel_1_2, 0)
    assert last_transfer.transferred_amount == 50

    amount = 30
    mediated_transfer(
        app0,
        app2,
        token_address,
        amount
    )
    last_transfer = get_sent_transfer(channel_0_1, 0)
    assert isinstance(last_transfer, DirectTransfer)

    initiator_transfer = get_sent_transfer(channel_0_3, 0)
    mediator_transfer = get_sent_transfer(channel_3_2, 0)
    assert initiator_transfer.identifier == mediator_transfer.identifier
    assert initiator_transfer.lock.amount == amount
    assert mediator_transfer.lock.amount == amount
