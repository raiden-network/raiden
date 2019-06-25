import gevent
import pytest

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.app import App
from raiden.constants import RoutingMode
from raiden.message_handler import MessageHandler
from raiden.network.transport import MatrixTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.storage.sqlite import RANGE_ALL_STATE_CHANGES
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import (
    assert_synced_channel_state,
    transfer,
    transfer_and_assert_path,
)
from raiden.transfer import views
from raiden.transfer.state import NODE_NETWORK_UNREACHABLE
from raiden.transfer.state_change import (
    ContractReceiveChannelClosed,
    ContractReceiveChannelSettled,
)
from raiden.utils import BlockNumber, create_default_identifier
from raiden.utils.typing import PaymentID, TokenAmount


@pytest.mark.parametrize("deposit", [10])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [3])
def test_recovery_happy_case(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]

    chain_state = views.state_from_app(app0)
    payment_network_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, payment_network_address, token_address
    )

    # make a few transfers from app0 to app2
    amount = 1
    spent_amount = deposit - 2
    identifier = 0
    for identifier in range(spent_amount):
        transfer_and_assert_path(
            path=raiden_network,
            token_address=token_address,
            amount=amount,
            identifier=identifier,
            timeout=network_wait * number_of_nodes,
        )

    app0.raiden.stop()
    app0.stop()

    waiting.wait_for_network_state(
        app1.raiden, app0.raiden.address, NODE_NETWORK_UNREACHABLE, network_wait
    )

    app0.start()

    assert_synced_channel_state(
        token_network_address, app0, deposit - spent_amount, [], app1, deposit + spent_amount, []
    )
    assert_synced_channel_state(
        token_network_address, app1, deposit - spent_amount, [], app2, deposit + spent_amount, []
    )

    # wait for the nodes' healthcheck to update the network statuses
    waiting.wait_for_healthy(app0.raiden, app1.raiden.address, network_wait)
    waiting.wait_for_healthy(app1.raiden, app0.raiden.address, network_wait)

    transfer_and_assert_path(
        path=raiden_network[::-1],
        token_address=token_address,
        amount=amount,
        identifier=create_default_identifier(),
        timeout=network_wait * number_of_nodes,
    )

    transfer_and_assert_path(
        path=raiden_network,
        token_address=token_address,
        amount=amount,
        identifier=create_default_identifier(),
        timeout=network_wait * number_of_nodes,
    )

    assert_synced_channel_state(
        token_network_address, app0, deposit - spent_amount, [], app1, deposit + spent_amount, []
    )

    assert_synced_channel_state(
        token_network_address, app1, deposit - spent_amount, [], app2, deposit + spent_amount, []
    )


@pytest.mark.parametrize("deposit", [10])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [3])
def test_recovery_unhappy_case(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait, retry_timeout
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, payment_network_address, token_address
    )

    # make a few transfers from app0 to app2
    amount = TokenAmount(1)
    spent_amount = deposit - 2
    for identifier in range(spent_amount):
        transfer(
            initiator_app=app0,
            target_app=app2,
            token_address=token_address,
            amount=amount,
            identifier=PaymentID(identifier),
            timeout=network_wait * number_of_nodes,
        )

    app0.raiden.stop()

    new_transport = MatrixTransport(app0.raiden.config["transport"]["matrix"])

    app0.stop()

    RaidenAPI(app1.raiden).channel_close(
        app1.raiden.default_registry.address, token_address, app0.raiden.address
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
    message_handler = MessageHandler()

    app0_restart = App(
        config=app0.config,
        chain=app0.raiden.chain,
        query_start_block=BlockNumber(0),
        default_registry=app0.raiden.default_registry,
        default_one_to_n_address=app0.raiden.default_one_to_n_address,
        default_secret_registry=app0.raiden.default_secret_registry,
        default_service_registry=app0.raiden.default_service_registry,
        default_msc_address=app0.raiden.default_msc_address,
        transport=new_transport,
        raiden_event_handler=raiden_event_handler,
        message_handler=message_handler,
        routing_mode=RoutingMode.PRIVATE,
    )
    del app0  # from here on the app0_restart should be used
    app0_restart.start()

    state_changes = app0_restart.raiden.wal.storage.get_statechanges_by_range(
        RANGE_ALL_STATE_CHANGES
    )

    assert search_for_item(
        state_changes,
        ContractReceiveChannelSettled,
        {
            "token_network_address": token_network_address,
            "channel_identifier": channel01.identifier,
        },
    )


@pytest.mark.parametrize("deposit", [10])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [2])
def test_recovery_blockchain_events(raiden_network, token_addresses, network_wait):
    """ Close one of the two raiden apps that have a channel between them,
    have the counterparty close the channel and then make sure the restarted
    app sees the change
    """
    app0, app1 = raiden_network
    token_address = token_addresses[0]

    app0.raiden.stop()

    new_transport = MatrixTransport(app0.raiden.config["transport"]["matrix"])

    app1_api = RaidenAPI(app1.raiden)
    app1_api.channel_close(
        registry_address=app0.raiden.default_registry.address,
        token_address=token_address,
        partner_address=app0.raiden.address,
    )

    app0.stop()

    gevent.sleep(1)

    raiden_event_handler = RaidenEventHandler()
    message_handler = MessageHandler()

    app0_restart = App(
        config=app0.config,
        chain=app0.raiden.chain,
        query_start_block=BlockNumber(0),
        default_registry=app0.raiden.default_registry,
        default_one_to_n_address=app0.raiden.default_one_to_n_address,
        default_secret_registry=app0.raiden.default_secret_registry,
        default_service_registry=app0.raiden.default_service_registry,
        default_msc_address=app0.raiden.default_msc_address,
        transport=new_transport,
        raiden_event_handler=raiden_event_handler,
        message_handler=message_handler,
        routing_mode=RoutingMode.PRIVATE,
    )

    del app0  # from here on the app0_restart should be used

    app0_restart.raiden.start()

    # wait for the nodes' healthcheck to update the network statuses
    waiting.wait_for_healthy(app0_restart.raiden, app1.raiden.address, network_wait)
    waiting.wait_for_healthy(app1.raiden, app0_restart.raiden.address, network_wait)
    restarted_state_changes = app0_restart.raiden.wal.storage.get_statechanges_by_range(
        RANGE_ALL_STATE_CHANGES
    )
    assert search_for_item(restarted_state_changes, ContractReceiveChannelClosed, {})
