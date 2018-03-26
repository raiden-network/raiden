# -*- coding: utf-8 -*-
import pytest

from raiden.exceptions import (
    NoPathError,
    InsufficientFunds,
)
from raiden.api.python import RaidenAPI

# Use a large enough settle timeout to have valid transfer messages
TEST_TOKEN_SWAP_SETTLE_TIMEOUT = (
    5 +  # reveal timeout
    7 +  # maker expiration
    7    # taker expiration
)


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_transfer_to_unknownchannel(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]
    graph1 = list(app1.raiden.token_to_channelgraph.values())[0]

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_to_channel

    with pytest.raises(NoPathError):
        RaidenAPI(app0.raiden).transfer(
            graph0.token_address,
            10,
            # sending to an unknown/non-existant address
            target=b'\xf0\xef3\x01\xcd\xcfe\x0f4\x9c\xf6d\xa2\x01?X4\x84\xa9\xf1',
            timeout=10
        )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.xfail
def test_insufficient_funds(raiden_network):
    """Test transfer on a channel with insufficient funds. It is expected to
    fail, as at the moment RaidenAPI is mocked and will always succeed."""
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]
    graph1 = list(app1.raiden.token_to_channelgraph.values())[0]

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_to_channel

    with pytest.raises(InsufficientFunds):
        RaidenAPI(app0.raiden).transfer(
            graph0.token_address,
            99999999999999999999,
            target=app1.raiden.address,
            timeout=10
        )
