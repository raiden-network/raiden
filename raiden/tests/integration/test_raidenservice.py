from copy import deepcopy
from unittest.mock import Mock, patch

import pytest

from raiden import waiting
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
from raiden.messages.path_finding_service import PFSCapacityUpdate, PFSFeeUpdate
from raiden.network.transport import MatrixTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.settings import (
    DEFAULT_MEDIATION_FLAT_FEE,
    DEFAULT_MEDIATION_PROPORTIONAL_FEE,
    DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
)
from raiden.storage.sqlite import RANGE_ALL_STATE_CHANGES
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import transfer
from raiden.transfer import views
from raiden.transfer.state import NettingChannelState
from raiden.transfer.state_change import Block
from raiden.utils import BlockNumber
from raiden.utils.typing import FeeAmount, PaymentAmount, PaymentID, ProportionalFeeAmount, Type


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
    "global_rooms",
    [[DISCOVERY_DEFAULT_ROOM, PATH_FINDING_BROADCASTING_ROOM, MONITORING_BROADCASTING_ROOM]],
)
def test_regression_transport_global_queues_are_initialized_on_restart_for_services(
    raiden_network, number_of_nodes, token_addresses, network_wait, user_deposit_address
):
    """On restarts, Raiden will restore state and publish new balance proof
    updates to the global matrix room. This test will check for regressions
    in the order of which the global queues are initialized on startup.

    Regression test for: https://github.com/raiden-network/raiden/issues/3656.
    """
    app0, app1 = raiden_network
    app0.config["services"]["monitoring_enabled"] = True
    # Send a transfer to make sure the state has a balance proof
    # to publish to the global matrix rooms
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
    transport.send_async = Mock()
    transport._send_raw = Mock()

    old_start_transport = transport.start

    # Check that the queue is populated before the transport sends it and empties the queue
    def start_transport(*args, **kwargs):
        # Before restart the transport's global message queue should be initialized
        # There should be 3 messages in the global queue:
        # - A `MonitorRequest` to the MS
        # - A `PFSCapacityUpdate`
        # - A `PFSFeeUpdate`
        queue_copy = transport._global_send_queue.copy()
        queued_messages = list()
        for _ in range(len(transport._global_send_queue)):
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
        assert num_matching_queued_messages(PATH_FINDING_BROADCASTING_ROOM, PFSFeeUpdate) == 1
        assert num_matching_queued_messages(PATH_FINDING_BROADCASTING_ROOM, PFSCapacityUpdate) == 1

        old_start_transport(*args, **kwargs)

    transport.start = start_transport

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


@pytest.mark.parametrize("number_of_nodes", [2])
def test_fees_are_updated_during_startup(
    raiden_network, token_addresses, deposit, retry_timeout
) -> None:
    """
    Test that the supplied fee settings are correctly forwarded to all
    channels during node startup.
    """
    app0, app1 = raiden_network

    token_address = token_addresses[0]

    def get_channel_state(app) -> NettingChannelState:
        chain_state = views.state_from_app(app)
        token_network_registry_address = app.raiden.default_registry.address
        token_network_address = views.get_token_network_address_by_token_address(
            chain_state, token_network_registry_address, token_address
        )
        assert token_network_address
        channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state, token_network_address, app1.raiden.address
        )
        assert channel_state

        return channel_state

    waiting.wait_both_channel_deposit(
        app0, app1, app0.raiden.default_registry.address, token_address, deposit, retry_timeout
    )
    # This is the imbalance penalty generated for the deposit
    # with DEFAULT_MEDIATION_PROPORTIONAL_IMBALANCE_FEE
    # once both channels have deposited the default (200) deposit
    default_imbalance_penalty = [
        (0, 1),
        (20, 0),
        (40, 0),
        (60, 0),
        (80, 0),
        (100, 0),
        (120, 0),
        (140, 0),
        (160, 0),
        (180, 0),
        (200, 0),
        (220, 0),
        (240, 0),
        (260, 0),
        (280, 0),
        (300, 0),
        (320, 0),
        (340, 0),
        (360, 0),
        (380, 0),
        (400, 1),
    ]

    # Check that the defaults are used
    channel_state = get_channel_state(app0)
    assert channel_state.fee_schedule.flat == DEFAULT_MEDIATION_FLAT_FEE
    assert channel_state.fee_schedule.proportional == DEFAULT_MEDIATION_PROPORTIONAL_FEE
    assert channel_state.fee_schedule.imbalance_penalty == default_imbalance_penalty

    orginal_config = app0.raiden.config.copy()

    # Now restart app0, and set new flat fee for that token network
    flat_fee = FeeAmount(100)
    app0.stop()
    app0.raiden.config = deepcopy(orginal_config)
    app0.raiden.config["mediation_fees"].token_to_flat_fee = {token_address: flat_fee}
    app0.start()

    channel_state = get_channel_state(app0)
    assert channel_state.fee_schedule.flat == flat_fee
    assert channel_state.fee_schedule.proportional == DEFAULT_MEDIATION_PROPORTIONAL_FEE
    assert channel_state.fee_schedule.imbalance_penalty == default_imbalance_penalty

    # Now restart app0, and set new proportional fee
    prop_fee = ProportionalFeeAmount(123)
    app0.stop()
    app0.raiden.config = deepcopy(orginal_config)
    app0.raiden.config["mediation_fees"].token_to_proportional_fee = {token_address: prop_fee}
    app0.start()

    channel_state = get_channel_state(app0)
    assert channel_state.fee_schedule.flat == DEFAULT_MEDIATION_FLAT_FEE
    assert channel_state.fee_schedule.proportional == prop_fee
    assert channel_state.fee_schedule.imbalance_penalty == default_imbalance_penalty

    # Now restart app0, and set new proportional imbalance fee
    app0.stop()
    app0.raiden.config = deepcopy(orginal_config)
    app0.raiden.config["mediation_fees"].token_to_proportional_imbalance_fee = {
        token_address: 0.05e6
    }
    app0.start()

    channel_state = get_channel_state(app0)
    assert channel_state.fee_schedule.flat == DEFAULT_MEDIATION_FLAT_FEE
    assert channel_state.fee_schedule.proportional == DEFAULT_MEDIATION_PROPORTIONAL_FEE
    # with 5% imbalance fee
    full_imbalance_penalty = [
        (0, 20),
        (20, 18),
        (40, 16),
        (60, 14),
        (80, 12),
        (100, 10),
        (120, 8),
        (140, 6),
        (160, 4),
        (180, 2),
        (200, 0),
        (220, 2),
        (240, 4),
        (260, 6),
        (280, 8),
        (300, 10),
        (320, 12),
        (340, 14),
        (360, 16),
        (380, 18),
        (400, 20),
    ]

    assert channel_state.fee_schedule.imbalance_penalty == full_imbalance_penalty
