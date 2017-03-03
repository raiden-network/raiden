# -*- coding: utf-8 -*-
import pytest
import random

from raiden.tests.utils.transfer import (
    direct_transfer,
    mediated_transfer,
    channel,
    get_sent_transfer,
    assert_identifier_correct
)


@pytest.mark.timeout(160)
@pytest.mark.parametrize('privatekey_seed', ['fullnetwork:{}'])
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [2])
@pytest.mark.parametrize('deposit', [2 ** 20])
def test_fullnetwork(raiden_chain):
    app0, app1, app2 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    token_address = app0.raiden.chain.default_registry.token_addresses()[0]

    amount = 80
    random.seed(0)
    direct_transfer(app0, app1, token_address, amount)
    # Assert default identifier is generated correctly
    fchannel = channel(app0, app1, token_address)
    last_transfer = get_sent_transfer(fchannel, 0)
    random.seed(0)
    assert_identifier_correct(app0, token_address, app1.raiden.address, last_transfer.identifier)

    amount = 50
    direct_transfer(app1, app2, token_address, amount)

    amount = 30
    random.seed(0)
    mediated_transfer(
        app1,
        app2,
        token_address,
        amount
    )
    # Assert default identifier is generated correctly
    fchannel = channel(app1, app2, token_address)
    last_transfer = get_sent_transfer(fchannel, 1)
    random.seed(0)
    assert_identifier_correct(app1, token_address, app2.raiden.address, last_transfer.identifier)
