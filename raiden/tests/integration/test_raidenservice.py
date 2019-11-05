from unittest.mock import Mock, patch

import pytest

from raiden.api.python import RaidenAPI
from raiden.app import App
from raiden.constants import (
    DISCOVERY_DEFAULT_ROOM,
    MONITORING_BROADCASTING_ROOM,
    PATH_FINDING_BROADCASTING_ROOM,
    RoutingMode,
)
from raiden.message_handler import MessageHandler
from raiden.messages.monitoring_service import RequestMonitoring
from raiden.network.transport import MatrixTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.storage.sqlite import RANGE_ALL_STATE_CHANGES
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import transfer
from raiden.transfer.state_change import Block
from raiden.utils.typing import BlockNumber, PaymentAmount, PaymentID, Type


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [1])
def test_regression_filters_must_be_installed_from_confirmed_block(raiden_network):
    """On restarts Raiden must install the filters from the last run's
    confirmed block instead of the latest known block.

    Regression test for: https://github.com/raiden-network/raiden/issues/2894.
    """
    app0 = raiden_network[0]

    app0.raiden.alarm.stop()
    target_block_num = (
        app0.raiden.rpc_client.block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
    )
    app0.raiden.proxy_manager.wait_until_block(target_block_num)

    latest_block = app0.raiden.rpc_client.get_block(block_identifier="latest")
    app0.raiden._callback_new_block(latest_block=latest_block)
    target_block_num = latest_block["number"]

    app0_state_changes = app0.raiden.wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)

    assert search_for_item(
        app0_state_changes,
        Block,
        {"block_number": target_block_num - DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS},
    )
    assert not search_for_item(app0_state_changes, Block, {"block_number": target_block_num})


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize(
    "broadcast_rooms",
    [[DISCOVERY_DEFAULT_ROOM, PATH_FINDING_BROADCASTING_ROOM, MONITORING_BROADCASTING_ROOM]],
)
def test_broadcast_messages_must_be_sent_before_protocol_messages_on_restarts(
    raiden_network, number_of_nodes, token_addresses, network_wait, user_deposit_address
):
    """ Raiden must broadcast the latest known balance proof on restarts.

    Regression test for: https://github.com/raiden-network/raiden/issues/3656.
    """
    app0, app1 = raiden_network
    app0.config["services"]["monitoring_enabled"] = True
    # Send a transfer to make sure the state has a balance proof to broadcast
    token_address = token_addresses[0]

    amount = PaymentAmount(10)
    payment_id = PaymentID(23)
    transfer(
        initiator_app=app1,
        target_app=app0,
        token_address=token_address,
        amount=amount,
        identifier=payment_id,
        timeout=network_wait * number_of_nodes,
    )

    app0.stop()

    transport = MatrixTransport(app0.config["transport"]["matrix"])
    transport.send_async = Mock()  # type: ignore
    transport._send_raw = Mock()  # type: ignore

    old_start_transport = transport.start

    # Asserts the balance proofs are broadcasted before protocol messages
    def start_transport(*args, **kwargs):
        # Before restart the transport's broadcast queue should be initialized
        # There should be A `MonitorRequest` message to the MS in the queue:
        # -
        queue_copy = transport._broadcast_queue.copy()
        queued_messages = list()
        for _ in range(len(transport._broadcast_queue)):
            queued_messages.append(queue_copy.get())

        def num_matching_queued_messages(room: str, message_type: Type) -> int:
            return len(
                [
                    item
                    for item in queued_messages
                    if item[0] == room and type(item[1]) == message_type
                ]
            )

        assert num_matching_queued_messages(MONITORING_BROADCASTING_ROOM, RequestMonitoring) == 1

        old_start_transport(*args, **kwargs)

    transport.start = start_transport  # type: ignore

    app0_restart = App(
        config=app0.config,
        rpc_client=app0.raiden.rpc_client,
        proxy_manager=app0.raiden.proxy_manager,
        query_start_block=BlockNumber(0),
        default_registry=app0.raiden.default_registry,
        default_one_to_n_address=app0.raiden.default_one_to_n_address,
        default_secret_registry=app0.raiden.default_secret_registry,
        default_service_registry=app0.raiden.default_service_registry,
        default_msc_address=app0.raiden.default_msc_address,
        transport=transport,
        raiden_event_handler=RaidenEventHandler(),
        message_handler=MessageHandler(),
        routing_mode=RoutingMode.PFS,  # not private mode, otherwise no PFS updates are queued
        user_deposit=app0.raiden.proxy_manager.user_deposit(user_deposit_address),
    )
    app0_restart.start()


@pytest.mark.parametrize("start_raiden_apps", [False])
@pytest.mark.parametrize("deposit", [0])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [2])
def test_alarm_task_first_run_syncs_blockchain_events(raiden_network, blockchain_services):
    """
    Test that the alarm tasks syncs blockchain events at the end of its first run

    Test for https://github.com/raiden-network/raiden/issues/4498
    """
    # These apps have had channels created but are not yet started
    app0, _ = raiden_network

    # Make sure we get into app0.start() with a confirmed block that contains
    # the channel creation events
    blockchain_services.proxy_manager.wait_until_block(target_block_number=10)
    target_block_num = (
        blockchain_services.proxy_manager.client.block_number()
        + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
    )
    blockchain_services.proxy_manager.wait_until_block(target_block_number=target_block_num)

    original_first_run = app0.raiden._prepare_and_execute_alarm_first_run

    def first_run_with_check(last_log_block):
        """
        This function simply enhances the alarm task first run

        The enhanced version has a check for channels being available right after
        the first run of the alarm task
        """
        original_first_run(last_log_block)
        channels = RaidenAPI(app0.raiden).get_channel_list(
            registry_address=app0.raiden.default_registry.address
        )
        assert len(channels) != 0, "After the first alarm task run no channels are visible"

    patched_first_run = patch.object(
        app0.raiden, "_prepare_and_execute_alarm_first_run", side_effect=first_run_with_check
    )
    with patched_first_run:
        app0.start()

    # If all runs well and our first_run_with_check function runs then test passes
    # since that means channels were queriable right after the first run of the
    # alarm task
