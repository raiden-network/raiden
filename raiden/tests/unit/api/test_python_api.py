# -*- coding: utf-8 -*-
import pytest

from raiden.tests.utils.transfer import (
    channel,
)
from raiden.exceptions import (
    NoPathError,
    InsufficientFunds,
)
from raiden.api.python import RaidenAPI


@pytest.mark.parametrize('blockchain_type', ['tester'])
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


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_transfer_to_unknownchannel(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = app0.raiden.token_to_channelgraph.values()[0]
    graph1 = app1.raiden.token_to_channelgraph.values()[0]

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_to_channel

    with pytest.raises(NoPathError):
        RaidenAPI(app0.raiden).transfer(
            graph0.token_address,
            10,
            # sending to an unknown/non-existant address
            target='\xf0\xef3\x01\xcd\xcfe\x0f4\x9c\xf6d\xa2\x01?X4\x84\xa9\xf1',
            timeout=10
        )


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.xfail
def test_insufficient_funds(raiden_network):
    """Test transfer on a channel with insufficient funds. It is expected to
    fail, as at the moment RaidenAPI is mocked and will always succeed."""
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = app0.raiden.token_to_channelgraph.values()[0]
    graph1 = app1.raiden.token_to_channelgraph.values()[0]

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_to_channel

    with pytest.raises(InsufficientFunds):
        RaidenAPI(app0.raiden).transfer(
            graph0.token_address,
            99999999999999999999,
            target=app1.raiden.address,
            timeout=10
        )
