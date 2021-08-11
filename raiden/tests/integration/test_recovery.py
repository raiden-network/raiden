import gevent
import pytest

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.constants import RoutingMode
from raiden.message_handler import MessageHandler
from raiden.network.transport import MatrixTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.raiden_service import RaidenService
from raiden.storage.sqlite import RANGE_ALL_STATE_CHANGES
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.protocol import HoldRaidenEventHandler
from raiden.tests.utils.transfer import (
    assert_succeeding_transfer_invariants,
    assert_synced_channel_state,
    transfer,
    transfer_and_assert_path,
)
from raiden.transfer import views
from raiden.transfer.events import ContractSendChannelWithdraw
from raiden.transfer.state_change import (
    ContractReceiveChannelClosed,
    ContractReceiveChannelSettled,
)
from raiden.ui.startup import RaidenBundle
from raiden.utils.transfers import create_default_identifier
from raiden.utils.typing import BlockNumber, List, PaymentAmount, PaymentID, WithdrawAmount


@pytest.mark.skip(reason="flaky, see https://github.com/raiden-network/raiden/issues/5821")
@raise_on_failure
@pytest.mark.parametrize("deposit", [10])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [3])
def test_recovery_happy_case(
    raiden_network: List[RaidenService],
    restart_node,
    number_of_nodes,
    deposit,
    token_addresses,
    network_wait,
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]

    chain_state = views.state_from_raiden(app0)
    token_network_registry_address = app0.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )
    assert token_network_address

    # make a few transfers from app0 to app2
    amount = PaymentAmount(1)
    spent_amount = deposit - 2
    for identifier in range(spent_amount):
        transfer_and_assert_path(
            path=raiden_network,
            token_address=token_address,
            amount=amount,
            identifier=PaymentID(identifier),
            timeout=network_wait * number_of_nodes,
        )

    app0.stop()

    restart_node(app0)

    assert_synced_channel_state(
        token_network_address, app0, deposit - spent_amount, [], app1, deposit + spent_amount, []
    )
    assert_synced_channel_state(
        token_network_address, app1, deposit - spent_amount, [], app2, deposit + spent_amount, []
    )

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

    assert_succeeding_transfer_invariants(
        token_network_address, app0, deposit - spent_amount, [], app1, deposit + spent_amount, []
    )

    assert_succeeding_transfer_invariants(
        token_network_address, app1, deposit - spent_amount, [], app2, deposit + spent_amount, []
    )


@raise_on_failure
@pytest.mark.parametrize("deposit", [10])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [3])
def test_recovery_unhappy_case(
    raiden_network: List[RaidenService],
    restart_node,
    number_of_nodes,
    deposit,
    token_addresses,
    network_wait,
    retry_timeout,
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_raiden(app0)
    token_network_registry_address = app0.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    # make a few transfers from app0 to app2
    amount = PaymentAmount(1)
    spent_amount = deposit - 2
    for identifier in range(spent_amount):
        transfer(
            initiator_app=app0,
            target_app=app2,
            token_address=token_address,
            amount=amount,
            identifier=PaymentID(identifier),
            timeout=network_wait * number_of_nodes,
            routes=[[app0, app1, app2]],
        )

    app0.stop()

    new_transport = MatrixTransport(
        config=app0.config.transport, environment=app0.config.environment_type
    )

    app0.stop()

    RaidenAPI(app1).channel_close(app1.default_registry.address, token_address, app0.address)

    channel01 = views.get_channelstate_for(
        views.state_from_raiden(app1),
        app1.default_registry.address,
        token_address,
        app0.address,
    )
    assert channel01

    waiting.wait_for_settle(
        app1,
        app1.default_registry.address,
        token_address,
        [channel01.identifier],
        retry_timeout,
    )

    raiden_event_handler = RaidenEventHandler()
    message_handler = MessageHandler()

    app0_restart = RaidenService(
        config=app0.config,
        rpc_client=app0.rpc_client,
        proxy_manager=app0.proxy_manager,
        query_start_block=BlockNumber(0),
        raiden_bundle=RaidenBundle(app0.default_registry, app0.default_secret_registry),
        services_bundle=app0.default_services_bundle,
        transport=new_transport,
        raiden_event_handler=raiden_event_handler,
        message_handler=message_handler,
        routing_mode=RoutingMode.PFS,
        pfs_proxy=app0.pfs_proxy,
    )
    del app0  # from here on the app0_restart should be used
    restart_node(app0_restart)
    wal = app0_restart.wal
    assert wal

    state_changes = wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)

    assert search_for_item(
        state_changes,
        ContractReceiveChannelSettled,
        {
            "token_network_address": token_network_address,
            "channel_identifier": channel01.identifier,
        },
    )


@raise_on_failure
@pytest.mark.parametrize("deposit", [10])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [2])
def test_recovery_blockchain_events(
    raiden_network: List[RaidenService], restart_node, token_addresses
):
    """Close one of the two raiden apps that have a channel between them,
    have the counterparty close the channel and then make sure the restarted
    app sees the change
    """
    app0, app1 = raiden_network
    token_address = token_addresses[0]

    app0.stop()

    new_transport = MatrixTransport(
        config=app0.config.transport, environment=app0.config.environment_type
    )

    app1_api = RaidenAPI(app1)
    app1_api.channel_close(
        registry_address=app0.default_registry.address,
        token_address=token_address,
        partner_address=app0.address,
    )

    app0.stop()

    raiden_event_handler = RaidenEventHandler()
    message_handler = MessageHandler()

    app0_restart = RaidenService(
        config=app0.config,
        rpc_client=app0.rpc_client,
        proxy_manager=app0.proxy_manager,
        query_start_block=BlockNumber(0),
        raiden_bundle=RaidenBundle(
            app0.default_registry,
            app0.default_secret_registry,
        ),
        services_bundle=app0.default_services_bundle,
        transport=new_transport,
        raiden_event_handler=raiden_event_handler,
        message_handler=message_handler,
        routing_mode=RoutingMode.PFS,
        pfs_proxy=app0.pfs_proxy,
    )

    del app0  # from here on the app0_restart should be used

    restart_node(app0_restart)
    wal = app0_restart.wal
    assert wal

    restarted_state_changes = wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)
    assert search_for_item(restarted_state_changes, ContractReceiveChannelClosed, {})


@raise_on_failure
@pytest.mark.parametrize("deposit", [2])
@pytest.mark.parametrize("number_of_nodes", [2])
def test_node_clears_pending_withdraw_transaction_after_channel_is_closed(
    raiden_network: List[RaidenService],
    restart_node,
    token_addresses,
    network_wait,
    number_of_nodes,
    retry_timeout,
    pfs_mock,
):
    """A test case related to https://github.com/raiden-network/raiden/issues/4639
    where a node sends a withdraw transaction, is stopped before the transaction is completed.
    Meanwhile, the partner node closes the channel so when the stopped node is back up, it tries to
    execute the pending withdraw transaction and fails because the channel was closed.
    Expected behaviour: Channel closed state change should cancel a withdraw transaction.
    Buggy behaviour: The channel closure isn't detected on recovery and
    the on-chain transaction fails.
    """
    app0, app1 = raiden_network
    pfs_mock.add_apps(raiden_network)
    token_address = token_addresses[0]

    # Prevent the withdraw transaction from being sent on-chain. This
    # will keep the transaction in the pending list
    assert isinstance(app0.raiden_event_handler, HoldRaidenEventHandler)
    send_channel_withdraw_event = app0.raiden_event_handler.hold(ContractSendChannelWithdraw, {})

    channel_state = views.get_channelstate_for(
        chain_state=views.state_from_raiden(app0),
        token_network_registry_address=app0.default_registry.address,
        token_address=token_address,
        partner_address=app1.address,
    )
    assert channel_state, "Channel does not exist"

    app1_metadata = pfs_mock.query_address_metadata(app0.config.pfs_config, app1.address)
    app0.withdraw(
        canonical_identifier=channel_state.canonical_identifier,
        total_withdraw=WithdrawAmount(1),
        recipient_metadata=app1_metadata,
    )

    timeout = network_wait * number_of_nodes
    with gevent.Timeout(seconds=timeout):
        send_channel_withdraw_event.wait()

    msg = "A withdraw transaction should be in the pending transactions list"
    chain_state = views.state_from_raiden(app0)
    assert search_for_item(
        item_list=chain_state.pending_transactions,
        item_type=ContractSendChannelWithdraw,
        attributes={"total_withdraw": 1},
    ), msg

    app0.stop()
    app0.stop()

    app1_api = RaidenAPI(app1)
    app1_api.channel_close(
        registry_address=app0.default_registry.address,
        token_address=token_address,
        partner_address=app0.address,
        coop_settle=False,
    )

    waiting.wait_for_close(
        raiden=app1,
        token_network_registry_address=app1.default_registry.address,
        token_address=token_address,
        channel_ids=[channel_state.identifier],
        retry_timeout=retry_timeout,
    )

    restart_node(app0)

    chain_state = views.state_from_raiden(app0)

    msg = "The withdraw transaction should have been invalidated on restart."
    assert (
        search_for_item(
            item_list=chain_state.pending_transactions,
            item_type=ContractSendChannelWithdraw,
            attributes={"total_withdraw": 1},
        )
        is None
    ), msg
