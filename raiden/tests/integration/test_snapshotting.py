# -*- coding: utf-8 -*-
import pytest

from ethereum import slogging

from raiden.raiden_service import RaidenService
from raiden.api.python import RaidenAPI

log = slogging.get_logger(__name__)


@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('settle_timeout', [16])
@pytest.mark.parametrize('reveal_timeout', [4])
@pytest.mark.parametrize('in_memory_database', [False])
def test_snapshotting(
    raiden_network,
    token_addresses,
    settle_timeout,
    blockchain_type
):
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

    states = dict()
    for num, app in enumerate(raiden_network):
        states[num] = dict(
            identifiers_to_statemanagers=app.raiden.identifier_to_statemanagers.copy(),
            channelgraphs=app.raiden.channelgraphs.copy(),
        )

    app0.raiden.protocol.stop_and_wait()
    app0.raiden.store_state()
    app1.raiden.protocol.stop_and_wait()
    app1.raiden.store_state()
    app2.raiden.protocol.stop_and_wait()
    app2.raiden.store_state()

    assert app0.raiden.transfer_states_path != app1.raiden.transfer_states_path

    for num, app in enumerate(raiden_network):
        app.raiden.identifier_to_statemanagers = dict()
        app.raiden.channelgraphs = dict()
        # restore_from_snapshot is called during __init__
        service = RaidenService(
            app.raiden.chain,
            app.raiden.privkey,
            app.raiden.protocol.transport,
            app.raiden.protocol.discovery,
            app.config
        )
        assert states[num]['identifiers_to_statemanagers'] == service.identifier_to_statemanagers
        assert states[num]['channelgraphs'] == service.channelgraphs
        assert len(service.channelgraphs)
        assert len(service.identifier_to_statemanagers)
        # FIXME: testing the queue snapshot is missing
