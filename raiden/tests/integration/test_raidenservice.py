from unittest.mock import Mock

import pytest

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.constants import BLOCK_ID_LATEST, DeviceIDs, RoutingMode
from raiden.exceptions import RaidenUnrecoverableError
from raiden.message_handler import MessageHandler
from raiden.messages.monitoring_service import RequestMonitoring
from raiden.messages.path_finding_service import PFSCapacityUpdate, PFSFeeUpdate
from raiden.network.transport import MatrixTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.raiden_service import RaidenService
from raiden.settings import (
    DEFAULT_MEDIATION_FLAT_FEE,
    DEFAULT_MEDIATION_PROPORTIONAL_FEE,
    DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
)
from raiden.storage.sqlite import RANGE_ALL_STATE_CHANGES
from raiden.tests.integration.fixtures.raiden_network import RestartNode
from raiden.tests.integration.test_integration_pfs import wait_all_apps
from raiden.tests.utils.detect_failure import expect_failure, raise_on_failure
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import transfer
from raiden.transfer import views
from raiden.transfer.state import NettingChannelState
from raiden.transfer.state_change import (
    Block,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
)
from raiden.ui.startup import RaidenBundle
from raiden.utils.copy import deepcopy
from raiden.utils.typing import (
    BlockNumber,
    FeeAmount,
    List,
    PaymentAmount,
    PaymentID,
    ProportionalFeeAmount,
    TokenAddress,
    Type,
)


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

    app0.alarm.stop()
    target_block_num = app0.rpc_client.block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
    app0.proxy_manager.client.wait_until_block(target_block_num)

    latest_block = app0.rpc_client.get_block(block_identifier=BLOCK_ID_LATEST)
    app0._best_effort_synchronize(latest_block=latest_block)
    target_block_num = latest_block["number"]

    app0_state_changes = app0.wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)

    assert search_for_item(
        app0_state_changes,
        Block,
        {"block_number": target_block_num - DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS},
    )
    assert not search_for_item(app0_state_changes, Block, {"block_number": target_block_num})


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
def test_broadcast_messages_must_be_sent_before_protocol_messages_on_restarts(
    raiden_network: List[RaidenService],
    restart_node,
    number_of_nodes,
    token_addresses,
    network_wait,
):
    """Raiden must broadcast the latest known balance proof on restarts.

    Regression test for: https://github.com/raiden-network/raiden/issues/3656.
    """
    app0, app1 = raiden_network
    app0.config.services.monitoring_enabled = True
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
        routes=[[app1, app0]],
    )

    app0.stop()

    transport = MatrixTransport(
        config=app0.config.transport, environment=app0.config.environment_type
    )
    transport.send_async = Mock()  # type: ignore
    transport._send_raw = Mock()  # type: ignore

    old_start_transport = transport.start

    # Asserts the balance proofs are broadcasted before protocol messages
    def start_transport(*args, **kwargs):
        # Before restart the transport's broadcast queue should be initialized
        # There should be 3 messages in the queue:
        # - A `MonitorRequest` to the MS
        # - A `PFSCapacityUpdate`
        # - A `PFSFeeUpdate`
        queue_copy = transport._broadcast_queue.copy()
        queued_messages = []
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

        assert num_matching_queued_messages(DeviceIDs.MS.value, RequestMonitoring) == 1
        assert num_matching_queued_messages(DeviceIDs.PFS.value, PFSFeeUpdate) == 1
        assert num_matching_queued_messages(DeviceIDs.PFS.value, PFSCapacityUpdate) == 1

        old_start_transport(*args, **kwargs)

    transport.start = start_transport  # type: ignore

    app0_restart = RaidenService(
        config=app0.config,
        rpc_client=app0.rpc_client,
        proxy_manager=app0.proxy_manager,
        query_start_block=BlockNumber(0),
        raiden_bundle=RaidenBundle(app0.default_registry, app0.default_secret_registry),
        services_bundle=app0.default_services_bundle,
        transport=transport,
        raiden_event_handler=RaidenEventHandler(),
        message_handler=MessageHandler(),
        routing_mode=RoutingMode.PFS,  # not private mode, otherwise no PFS updates are queued
        pfs_proxy=app0.pfs_proxy,
    )
    restart_node(app0_restart)


@expect_failure  # raise_on_failure will not work here since the apps are not started
@pytest.mark.parametrize("start_raiden_apps", [False])
@pytest.mark.parametrize("deposit", [0])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [2])
def test_alarm_task_first_run_syncs_blockchain_events(
    raiden_network: List[RaidenService], blockchain_services
):
    """Raiden must synchronize with the blockchain events during
    initialization.

    Test for https://github.com/raiden-network/raiden/issues/4498
    """
    app0, _ = raiden_network

    # Make sure we get into the restart of app0 with a confirmed block that contains
    # the channel creation events
    target_block_num = (
        blockchain_services.proxy_manager.client.block_number()
        + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
    )
    blockchain_services.proxy_manager.client.wait_until_block(target_block_number=target_block_num)

    # This is a bit brittle, it calls the same steps as `start` would do
    app0._initialize_wal()
    app0._synchronize_with_blockchain()

    channels = RaidenAPI(app0).get_channel_list(registry_address=app0.default_registry.address)
    msg = "Initialization did not properly synchronize with the blockchain, channel is missing"
    assert len(channels) != 0, msg


@raise_on_failure
@pytest.mark.parametrize("deposit", [0])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [2])
def test_initialize_wal_throws_when_lock_is_taken(raiden_network: List[RaidenService]):
    """Raiden must throw a proper exception when the filelock of the DB is already taken.

    Test for https://github.com/raiden-network/raiden/issues/6079
    """
    app0, _ = raiden_network

    # Start a second app, that should throw an expection, as the lock is already taken
    app0_2 = RaidenService(
        config=app0.config,
        rpc_client=app0.rpc_client,
        proxy_manager=app0.proxy_manager,
        query_start_block=BlockNumber(0),
        raiden_bundle=RaidenBundle(app0.default_registry, app0.default_secret_registry),
        services_bundle=app0.default_services_bundle,
        transport=app0.transport,
        raiden_event_handler=RaidenEventHandler(),
        message_handler=MessageHandler(),
        routing_mode=RoutingMode.PFS,
        pfs_proxy=app0.pfs_proxy,
    )
    with pytest.raises(RaidenUnrecoverableError):
        app0_2.start()


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
def test_fees_are_updated_during_startup(
    raiden_network: List[RaidenService], restart_node, token_addresses, deposit, retry_timeout
) -> None:
    """
    Test that the supplied fee settings are correctly forwarded to all
    channels during node startup.
    """
    app0, app1 = raiden_network

    token_address = token_addresses[0]

    def get_channel_state(app) -> NettingChannelState:
        chain_state = views.state_from_raiden(app)
        token_network_registry_address = app.default_registry.address
        token_network_address = views.get_token_network_address_by_token_address(
            chain_state, token_network_registry_address, token_address
        )
        assert token_network_address
        channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state, token_network_address, app1.address
        )
        assert channel_state

        return channel_state

    waiting.wait_both_channel_deposit(
        app0, app1, app0.default_registry.address, token_address, deposit, retry_timeout
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

    original_config = deepcopy(app0.config)

    # Now restart app0, and set new flat fee for that token network
    flat_fee = FeeAmount(100)
    app0.stop()
    app0.config = deepcopy(original_config)
    app0.config.mediation_fees.token_to_flat_fee[token_address] = flat_fee
    restart_node(app0)

    channel_state = get_channel_state(app0)
    assert channel_state.fee_schedule.flat == flat_fee
    assert channel_state.fee_schedule.proportional == DEFAULT_MEDIATION_PROPORTIONAL_FEE
    assert channel_state.fee_schedule.imbalance_penalty == default_imbalance_penalty

    # Now restart app0, and set new proportional fee
    prop_fee = ProportionalFeeAmount(123)
    app0.stop()
    app0.config = deepcopy(original_config)
    app0.config.mediation_fees.token_to_proportional_fee[token_address] = prop_fee
    restart_node(app0)

    channel_state = get_channel_state(app0)
    assert channel_state.fee_schedule.flat == DEFAULT_MEDIATION_FLAT_FEE
    assert channel_state.fee_schedule.proportional == prop_fee
    assert channel_state.fee_schedule.imbalance_penalty == default_imbalance_penalty

    # Now restart app0, and set new proportional imbalance fee
    app0.stop()
    app0.config = deepcopy(original_config)
    app0.config.mediation_fees.token_to_proportional_imbalance_fee[
        token_address
    ] = ProportionalFeeAmount(50_000)
    restart_node(app0)

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


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [1])
def test_blockchain_event_processed_interleaved(
    raiden_network: List[RaidenService],
    token_addresses: List[TokenAddress],
    restart_node: RestartNode,
):
    """Blockchain events must be transformed into state changes and processed by
    the state machine interleaved.

    Otherwise problems arise when the creation of the state change is dependent
    on the state of the state machine.

    Regression test for: https://github.com/raiden-network/raiden/issues/6444
    """
    app0, app1 = raiden_network

    app1.stop()

    api0 = RaidenAPI(app0)
    channel_id = api0.channel_open(
        registry_address=app0.default_registry.address,
        token_address=token_addresses[0],
        partner_address=app1.address,
    )
    api0.channel_close(
        registry_address=app0.default_registry.address,
        token_address=token_addresses[0],
        partner_address=app1.address,
    )

    # Restart node 1
    restart_node(app1)
    wait_all_apps(raiden_network)

    # Check correct events
    assert app1.wal, "app1.wal not set"
    app1_state_changes = app1.wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)

    assert search_for_item(
        app1_state_changes, ContractReceiveChannelNew, {"channel_identifier": channel_id}
    )

    assert search_for_item(
        app1_state_changes, ContractReceiveChannelClosed, {"channel_identifier": channel_id}
    )
