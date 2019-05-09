from unittest.mock import Mock

import pytest

from raiden.app import App
from raiden.constants import (
    DISCOVERY_DEFAULT_ROOM,
    MONITORING_BROADCASTING_ROOM,
    PATH_FINDING_BROADCASTING_ROOM,
)
from raiden.message_handler import MessageHandler
from raiden.network.transport import MatrixTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import transfer
from raiden.transfer.state_change import Block


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [1])
def test_regression_filters_must_be_installed_from_confirmed_block(raiden_network):
    """On restarts Raiden must install the filters from the last run's
    confirmed block instead of the latest known block.

    Regression test for: https://github.com/raiden-network/raiden/issues/2894.
    """
    raise_on_failure(
        raiden_network,
        run_test_regression_filters_must_be_installed_from_confirmed_block,
        raiden_network=raiden_network,
    )


def run_test_regression_filters_must_be_installed_from_confirmed_block(raiden_network):
    app0 = raiden_network[0]

    app0.raiden.alarm.stop()
    target_block_num = app0.raiden.chain.block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
    app0.raiden.chain.wait_until_block(target_block_num)

    latest_block = app0.raiden.chain.get_block(block_identifier="latest")
    app0.raiden._callback_new_block(latest_block=latest_block)
    target_block_num = latest_block["number"]

    app0_state_changes = app0.raiden.wal.storage.get_statechanges_by_identifier(
        from_identifier=0, to_identifier="latest"
    )

    assert search_for_item(
        app0_state_changes,
        Block,
        {"block_number": target_block_num - DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS},
    )
    assert not search_for_item(app0_state_changes, Block, {"block_number": target_block_num})


@pytest.mark.xfail(reason="flaky, see issue #3714")
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize(
    "global_rooms",
    [[DISCOVERY_DEFAULT_ROOM, PATH_FINDING_BROADCASTING_ROOM, MONITORING_BROADCASTING_ROOM]],
)
def test_regression_transport_global_queues_are_initialized_on_restart_for_services(
    raiden_network,
    number_of_nodes,
    token_addresses,
    network_wait,
    user_deposit_address,
    skip_if_not_matrix,  # pylint: disable=unused-argument
):
    """On restarts, Raiden will restore state and publish new balance proof
    updates to the global matrix room. This test will check for regressions
    in the order of which the global queues are initialized on startup.

    Regression test for: https://github.com/raiden-network/raiden/issues/3656.
    """
    raise_on_failure(
        raiden_network,
        run_test_regression_transport_global_queues_are_initialized_on_restart_for_services,
        raiden_network=raiden_network,
        number_of_nodes=number_of_nodes,
        token_addresses=token_addresses,
        network_wait=network_wait,
        user_deposit_address=user_deposit_address,
    )


def run_test_regression_transport_global_queues_are_initialized_on_restart_for_services(
    raiden_network, number_of_nodes, token_addresses, network_wait, user_deposit_address
):
    app0, app1 = raiden_network

    app0.config["services"]["monitoring_enabled"] = True

    # Send a transfer to make sure the state has a balance proof
    # to publish to the global matrix rooms
    token_address = token_addresses[0]

    amount = 10
    transfer(
        initiator_app=app1,
        target_app=app0,
        token_address=token_address,
        amount=amount,
        identifier=1,
        timeout=network_wait * number_of_nodes,
    )

    app0.stop()

    transport = MatrixTransport(app0.config["transport"]["matrix"])
    transport.send_async = Mock()
    transport._send_raw = Mock()

    old_start_transport = transport.start

    # Check that the queue is populated before the transport sends it and empties the queue
    def start_transport(*args, **kwargs):
        # Before restart the transport's global message queue should be initialized
        # There should be 2 messages in the global queue.
        # 1 for the PFS and the other for MS
        assert len(transport._global_send_queue) == 2
        # No other messages were sent at this point
        transport.send_async.assert_not_called()
        transport._send_raw.assert_not_called()
        old_start_transport(*args, **kwargs)

    transport.start = start_transport

    raiden_event_handler = RaidenEventHandler()
    message_handler = MessageHandler()
    app0_restart = App(
        config=app0.config,
        chain=app0.raiden.chain,
        query_start_block=0,
        default_registry=app0.raiden.default_registry,
        default_secret_registry=app0.raiden.default_secret_registry,
        default_service_registry=app0.raiden.default_service_registry,
        transport=transport,
        raiden_event_handler=raiden_event_handler,
        message_handler=message_handler,
        discovery=app0.raiden.discovery,
        user_deposit=app0.raiden.chain.user_deposit(user_deposit_address),
    )
    app0_restart.start()
