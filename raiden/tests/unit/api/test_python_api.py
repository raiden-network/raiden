# -*- coding: utf-8 -*-
import pytest
import gevent

from raiden.tests.utils.transfer import (
    assert_synched_channels,
    channel,
)
from raiden.exceptions import NoPathError
from raiden.api.python import RaidenAPI

# Use a large enough settle timeout to have valid transfer messages
TEST_TOKEN_SWAP_SETTLE_TIMEOUT = (
    5 +  # reveal timeout
    7 +  # maker expiration
    7    # taker expiration
)


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_get_channel_list(raiden_network, token_addresses):
    app0, app1, app2 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = channel(app0, app1, token_addresses[0])
    channel1 = channel(app1, app0, token_addresses[0])
    channel2 = channel(app0, app2, token_addresses[0])

    api0 = RaidenAPI(app0.raiden)
    api1 = RaidenAPI(app1.raiden)
    api2 = RaidenAPI(app2.raiden)

    assert channel0, channel2 in api0.get_channel_list()
    assert channel0 in api0.get_channel_list(partner_address=app1.raiden.address)
    assert channel1 in api1.get_channel_list(token_address=token_addresses[0])
    assert channel1 in api1.get_channel_list(token_addresses[0], app0.raiden.address)
    assert not api1.get_channel_list(partner_address=app2.raiden.address)

    with pytest.raises(KeyError):
        api1.get_channel_list(
            token_address=token_addresses[0],
            partner_address=app2.raiden.address,
        )

    with pytest.raises(KeyError):
        api2.get_channel_list(
            token_address=app2.raiden.address,
        )


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_transfer_to_unknownchannel(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = app0.raiden.channelgraphs.values()[0]
    graph1 = app1.raiden.channelgraphs.values()[0]

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_channel

    with pytest.raises(NoPathError):
        result = RaidenAPI(app0.raiden).transfer(
            graph0.token_address,
            10,
            # sending to an unknown/non-existant address
            target='\xf0\xef3\x01\xcd\xcfe\x0f4\x9c\xf6d\xa2\x01?X4\x84\xa9\xf1',
        )

        assert result.wait(timeout=10)


@pytest.mark.parametrize('blockchain_type', ['geth'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [2])
@pytest.mark.parametrize('settle_timeout', [TEST_TOKEN_SWAP_SETTLE_TIMEOUT])
def test_token_swap(raiden_network, deposit, settle_timeout):
    app0, app1 = raiden_network

    maker_address = app0.raiden.address
    taker_address = app1.raiden.address

    maker_token, taker_token = app0.raiden.channelgraphs.keys()[:2]
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
