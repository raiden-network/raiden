# -*- coding: utf-8 -*-
import pytest
import gevent

from raiden.tests.utils.transfer import (
    assert_synched_channels,
    channel,
)
from raiden.api.python import RaidenAPI

# Use a large enough settle timeout to have valid transfer messages
TEST_TOKEN_SWAP_SETTLE_TIMEOUT = (
    5 +  # reveal timeout
    7 +  # maker expiration
    7    # taker expiration
)


@pytest.mark.parametrize('blockchain_type', ['geth'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [2])
@pytest.mark.parametrize('settle_timeout', [TEST_TOKEN_SWAP_SETTLE_TIMEOUT])
def test_token_swap(raiden_network, deposit, settle_timeout):
    app0, app1 = raiden_network

    maker_address = app0.raiden.address
    taker_address = app1.raiden.address

    maker_token, taker_token = app0.raiden.token_to_channelgraph.keys()[:2]
    maker_amount = 70
    taker_amount = 30

    identifier = 313
    RaidenAPI(app1.raiden).expect_token_swap(
        identifier,
        maker_token,
        maker_amount,
        maker_address,
        taker_token,
        taker_amount,
        taker_address,
    )

    async_result = RaidenAPI(app0.raiden).token_swap_async(
        identifier,
        maker_token,
        maker_amount,
        maker_address,
        taker_token,
        taker_amount,
        taker_address,
    )

    async_result.wait()

    # wait for the taker to receive and process the messages
    gevent.sleep(0.5)

    assert_synched_channels(
        channel(app0, app1, maker_token), deposit - maker_amount, [],
        channel(app1, app0, maker_token), deposit + maker_amount, [],
    )

    assert_synched_channels(
        channel(app0, app1, taker_token), deposit + taker_amount, [],
        channel(app1, app0, taker_token), deposit - taker_amount, [],
    )
