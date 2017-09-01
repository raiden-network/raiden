# -*- coding: utf-8 -*-
import pytest

from raiden.tests.utils.transfer import assert_mirror, channel


@pytest.mark.parametrize('privatekey_seed', ['test_direct_transfer_to_offline_node:{}'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_tokens', [1])
def test_direct_transfer_to_offline_node(raiden_network, token_addresses):
    token_address = token_addresses[0]
    app0, app1 = raiden_network

    app1.raiden.stop()

    amount = 10
    target = app1.raiden.address
    async_result = app0.raiden.direct_transfer_async(
        token_address,
        amount,
        target,
        identifier=1,
    )

    assert async_result.wait(5) is None

    app1.raiden.start()

    assert async_result.wait(5) is True

    assert_mirror(
        channel(app0, app1, token_address),
        channel(app1, app0, token_address),
    )
