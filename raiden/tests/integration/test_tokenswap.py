# -*- coding: utf-8 -*-
import pytest
import gevent

from raiden.tests.utils.transfer import (
    assert_synched_channels,
    channel,
)

# Use a large enough settle timeout to have valid transfer messages
TEST_TOKEN_SWAP_SETTLE_TIMEOUT = (
    5 +  # reveal timeout
    7 +  # maker expiration
    7    # taker expiration
)

@pytest.mark.timeout(160)
@pytest.mark.parametrize('blockchain_type', ['geth'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [2])
@pytest.mark.parametrize('settle_timeout', [TEST_TOKEN_SWAP_SETTLE_TIMEOUT])
def test_token_swap(raiden_network, deposit, settle_timeout):
    app0, app1 = raiden_network

    target = app1.raiden.address

    from_token, to_token = app0.raiden.channelgraphs.keys()[:2]
    from_amount = 70
    to_amount = 30

    identifier = 313

    app1.raiden.api.expect_token_swap(
        identifier,
        from_token,
        from_amount,
        to_token,
        to_amount,
        target,
    )

    async_result = app0.raiden.api.token_swap_async(
        identifier,
        from_token,
        from_amount,
        to_token,
        to_amount,
        target,
    )

    async_result.wait()

    # wait for the taker to receive and process the messages
    gevent.sleep(0.5)

    assert_synched_channels(
        channel(app0, app1, from_token), deposit - from_amount, [],
        channel(app1, app0, from_token), deposit + from_amount, [],
    )

    assert_synched_channels(
        channel(app0, app1, to_token), deposit + to_amount, [],
        channel(app1, app0, to_token), deposit - to_amount, [],
    )
