import pytest
from gevent import server

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.app import App
from raiden.network.transport import UDPTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import assert_synced_channel_state, mediated_transfer
from raiden.transfer import views
from raiden.transfer.state_change import (
    ContractReceiveChannelClosed,
    ContractReceiveChannelSettled,
)


@pytest.mark.parametrize('deposit', [10])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_recovery_happy_case(
        raiden_network,
        number_of_nodes,
        deposit,
        token_addresses,
        network_wait,
        skip_if_not_udp,
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    # make a few transfers from app0 to app2
    amount = 1
    spent_amount = deposit - 2
    for _ in range(spent_amount):
        mediated_transfer(
            app0,
            app2,
            token_network_identifier,
            amount,
            timeout=network_wait * number_of_nodes,
        )

    app0.raiden.stop()
    host_port = (
        app0.raiden.config['transport']['udp']['host'],
        app0.raiden.config['transport']['udp']['port'],
    )
    socket = server._udp_socket(host_port)

    new_transport = UDPTransport(
        app0.discovery,
        socket,
        app0.raiden.transport.throttle_policy,
        app0.raiden.config['transport']['udp'],
    )

    raiden_event_handler = RaidenEventHandler()

    app0_restart = App(
        config=app0.config,
        chain=app0.raiden.chain,
        query_start_block=0,
        default_registry=app0.raiden.default_registry,
        default_secret_registry=app0.raiden.default_secret_registry,
        transport=new_transport,
        raiden_event_handler=raiden_event_handler,
        discovery=app0.raiden.discovery,
    )

    app0.stop()
    del app0  # from here on the app0_restart should be used

    app0_restart.start()

    assert_synced_channel_state(
        token_network_identifier,
        app0_restart, deposit - spent_amount, [],
        app1, deposit + spent_amount, [],
    )
    assert_synced_channel_state(
        token_network_identifier,
        app1, deposit - spent_amount, [],
        app2, deposit + spent_amount, [],
    )

    # wait for the nodes' healthcheck to update the network statuses
    waiting.wait_for_healthy(
        app0_restart.raiden,
        app1.raiden.address,
        network_wait,
    )
    waiting.wait_for_healthy(
        app1.raiden,
        app0_restart.raiden.address,
        network_wait,
    )

    mediated_transfer(
        app2,
        app0_restart,
        token_network_identifier,
        amount,
        timeout=network_wait * number_of_nodes * 2,
    )
    mediated_transfer(
        app0_restart,
        app2,
        token_network_identifier,
        amount,
        timeout=network_wait * number_of_nodes * 2,
    )

    assert_synced_channel_state(
        token_network_identifier,
        app0_restart, deposit - spent_amount, [],
        app1, deposit + spent_amount, [],
    )
    assert_synced_channel_state(
        token_network_identifier,
        app1, deposit - spent_amount, [],
        app2, deposit + spent_amount, [],
    )


@pytest.mark.parametrize('deposit', [10])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_recovery_unhappy_case(
        raiden_network,
        number_of_nodes,
        deposit,
        token_addresses,
        network_wait,
        skip_if_not_udp,
        retry_timeout,
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    # make a few transfers from app0 to app2
    amount = 1
    spent_amount = deposit - 2
    for _ in range(spent_amount):
        mediated_transfer(
            app0,
            app2,
            token_network_identifier,
            amount,
            timeout=network_wait * number_of_nodes,
        )

    app0.raiden.stop()
    host_port = (
        app0.raiden.config['transport']['udp']['host'],
        app0.raiden.config['transport']['udp']['port'],
    )
    socket = server._udp_socket(host_port)

    new_transport = UDPTransport(
        app0.discovery,
        socket,
        app0.raiden.transport.throttle_policy,
        app0.raiden.config['transport']['udp'],
    )

    app0.stop()

    RaidenAPI(app1.raiden).channel_close(
        app1.raiden.default_registry.address,
        token_address,
        app0.raiden.address,
    )

    channel01 = views.get_channelstate_for(
        views.state_from_app(app1),
        app1.raiden.default_registry.address,
        token_address,
        app0.raiden.address,
    )

    waiting.wait_for_settle(
        app1.raiden,
        app1.raiden.default_registry.address,
        token_address,
        [channel01.identifier],
        retry_timeout,
    )

    raiden_event_handler = RaidenEventHandler()

    app0_restart = App(
        config=app0.config,
        chain=app0.raiden.chain,
        query_start_block=0,
        default_registry=app0.raiden.default_registry,
        default_secret_registry=app0.raiden.default_secret_registry,
        transport=new_transport,
        raiden_event_handler=raiden_event_handler,
        discovery=app0.raiden.discovery,
    )
    del app0  # from here on the app0_restart should be used
    app0_restart.start()

    state_changes = app0_restart.raiden.wal.storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )

    assert must_contain_entry(state_changes, ContractReceiveChannelSettled, {
        'token_network_identifier': token_network_identifier,
        'channel_identifier': channel01.identifier,
    })


@pytest.mark.parametrize('deposit', [10])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_recovery_blockchain_events(
        raiden_network,
        number_of_nodes,
        deposit,
        token_addresses,
        network_wait,
        skip_if_not_udp,
):
    """ Close one of the two raiden apps that have a channel between them,
    have the counterparty close the channel and then make sure the restarted
    app sees the change
    """
    app0, app1 = raiden_network
    token_address = token_addresses[0]

    app0.raiden.stop()
    host_port = (
        app0.raiden.config['transport']['udp']['host'],
        app0.raiden.config['transport']['udp']['port'],
    )
    socket = server._udp_socket(host_port)

    new_transport = UDPTransport(
        app0.discovery,
        socket,
        app0.raiden.transport.throttle_policy,
        app0.raiden.config['transport']['udp'],
    )

    app1_api = RaidenAPI(app1.raiden)
    app1_api.channel_close(
        registry_address=app0.raiden.default_registry.address,
        token_address=token_address,
        partner_address=app0.raiden.address,
    )

    app0.stop()

    import gevent
    gevent.sleep(1)

    raiden_event_handler = RaidenEventHandler()

    app0_restart = App(
        config=app0.config,
        chain=app0.raiden.chain,
        query_start_block=0,
        default_registry=app0.raiden.default_registry,
        default_secret_registry=app0.raiden.default_secret_registry,
        transport=new_transport,
        raiden_event_handler=raiden_event_handler,
        discovery=app0.raiden.discovery,
    )

    del app0  # from here on the app0_restart should be used

    app0_restart.raiden.start()

    # wait for the nodes' healthcheck to update the network statuses
    waiting.wait_for_healthy(
        app0_restart.raiden,
        app1.raiden.address,
        network_wait,
    )
    waiting.wait_for_healthy(
        app1.raiden,
        app0_restart.raiden.address,
        network_wait,
    )
    restarted_state_changes = app0_restart.raiden.wal.storage.get_statechanges_by_identifier(
        0,
        'latest',
    )
    assert must_contain_entry(restarted_state_changes, ContractReceiveChannelClosed, {})
