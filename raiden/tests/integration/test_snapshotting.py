# -*- coding: utf-8 -*-
import pytest

from ethereum import slogging

from raiden.raiden_service import load_snapshot
from raiden.api.python import RaidenAPI

log = slogging.get_logger(__name__)


@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('settle_timeout', [16])
@pytest.mark.parametrize('reveal_timeout', [4])
@pytest.mark.parametrize('in_memory_database', [False])
def test_snapshotting(raiden_network, token_addresses):
    app0, app1, app2 = raiden_network

    api0 = RaidenAPI(app0.raiden)
    api1 = RaidenAPI(app1.raiden)

    channel_0_1 = api0.get_channel_list(token_addresses[0], app1.raiden.address)
    channel_0_2 = api0.get_channel_list(token_addresses[0], app2.raiden.address)

    with pytest.raises(KeyError):
        api1.get_channel_list(token_addresses[0], app2.raiden.address)

    assert len(channel_0_1) == 1
    assert len(channel_0_2) == 1
    api1.transfer_and_wait(token_addresses[0], 5, app2.raiden.address)

    app0.stop()
    app1.stop()
    app2.stop()

    for app in [app0, app1, app2]:
        data = load_snapshot(app.raiden.serialization_file)

        for serialized_channel in data['channels']:
            network = app.raiden.token_to_channelgraph[serialized_channel.token_address]
            running_channel = network.address_to_channel[serialized_channel.channel_address]
            assert running_channel.serialize() == serialized_channel

        for queue in data['queues']:
            key = (queue['receiver_address'], queue['token_address'])
            assert app.raiden.protocol.channel_queue[key].copy() == queue['messages']

        assert data['receivedhashes_to_acks'] == app.raiden.protocol.receivedhashes_to_acks
        assert data['nodeaddresses_to_nonces'] == app.raiden.protocol.nodeaddresses_to_nonces
        assert data['transfers'] == app.raiden.identifier_to_statemanagers
