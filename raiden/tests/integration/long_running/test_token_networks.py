import gevent
import pytest

from raiden import routing, waiting
from raiden.api.python import RaidenAPI
from raiden.exceptions import InvalidAmount
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.transfer import watch_for_unlock_failures
from raiden.transfer import channel, views
from raiden.transfer.state import ChannelState
from raiden.utils.typing import PaymentAmount, TokenAmount


def wait_for_transaction(receiver, registry_address, token_address, sender_address):
    """Wait until a first transaction in a channel is received"""
    while True:
        receiver_channel = RaidenAPI(receiver).get_channel_list(
            registry_address=registry_address,
            token_address=token_address,
            partner_address=sender_address,
        )
        transaction_received = (
            len(receiver_channel) == 1
            and receiver_channel[0].partner_state.balance_proof is not None
        )

        if transaction_received:
            break
        gevent.sleep(0.1)


def is_channel_open_and_funded(channel_state):
    return (
        channel.get_status(channel_state) == ChannelState.STATE_OPENED
        and channel_state.our_state.contract_balance > 0
    )


def is_manager_saturated(connection_manager, registry_address, token_address):
    raiden = connection_manager.raiden
    open_channels = views.get_channelstate_filter(
        views.state_from_raiden(raiden),
        registry_address,
        token_address,
        lambda channel_state: (
            is_channel_open_and_funded(channel_state)
            and channel_state.partner_state.address != connection_manager.BOOTSTRAP_ADDR
            and (
                channel_state.our_state.address == raiden.address
                or channel_state.partner_state.address == raiden.address
            )
        ),
    )
    return len(open_channels) >= connection_manager.initial_channel_target


def saturated_count(connection_managers, registry_address, token_address):
    """Return count of nodes with count of open channels exceeding initial channel target"""
    return [
        is_manager_saturated(manager, registry_address, token_address)
        for manager in connection_managers
    ].count(True)


def estimate_blocktime(rpc_client: JSONRPCClient, oldest: int = 256) -> float:
    """Calculate a blocktime estimate based on some past blocks.
    Args:
        oldest: delta in block numbers to go back.
    Return:
        average block time in seconds
    """
    last_block_number = rpc_client.block_number()
    # around genesis block there is nothing to estimate
    if last_block_number < 1:
        return 15
    # if there are less than `oldest` blocks available, start at block 1
    if last_block_number < oldest:
        interval = (last_block_number - 1) or 1
    else:
        interval = last_block_number - oldest
    assert interval > 0
    last_timestamp = rpc_client.get_block(last_block_number)["timestamp"]
    first_timestamp = rpc_client.get_block(last_block_number - interval)["timestamp"]
    delta = last_timestamp - first_timestamp
    return delta / interval


# TODO: add test scenarios for
# - subsequent `connect()` calls with different `funds` arguments
# - `connect()` calls with preexisting channels
@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [6])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("settle_timeout", [10])
@pytest.mark.parametrize("reveal_timeout", [3])
def test_participant_selection(raiden_network, token_addresses):
    # pylint: disable=too-many-locals
    registry_address = raiden_network[0].raiden.default_registry.address
    one_to_n_address = raiden_network[0].raiden.default_one_to_n_address
    token_address = token_addresses[0]
    # connect the first node - this will register the token and open the first channel
    # Since there is no other nodes available to connect to this call will do nothing more
    RaidenAPI(raiden_network[0].raiden).token_network_connect(
        registry_address=registry_address, token_address=token_address, funds=TokenAmount(100)
    )

    # Test invalid argument values
    with pytest.raises(InvalidAmount):
        RaidenAPI(raiden_network[0].raiden).token_network_connect(
            registry_address=registry_address, token_address=token_address, funds=TokenAmount(-1)
        )
    with pytest.raises(InvalidAmount):
        RaidenAPI(raiden_network[0].raiden).token_network_connect(
            registry_address=registry_address,
            token_address=token_address,
            funds=TokenAmount(100),
            joinable_funds_target=2,
        )
    with pytest.raises(InvalidAmount):
        RaidenAPI(raiden_network[0].raiden).token_network_connect(
            registry_address=registry_address,
            token_address=token_address,
            funds=TokenAmount(100),
            joinable_funds_target=-1,
        )

    # Call the connect endpoint for all but the first node
    connect_greenlets = [
        gevent.spawn(
            RaidenAPI(app.raiden).token_network_connect, registry_address, token_address, 100
        )
        for app in raiden_network[1:]
    ]
    gevent.wait(connect_greenlets)

    token_network_registry_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(raiden_network[0].raiden),
        token_network_registry_address=registry_address,
        token_address=token_address,
    )
    connection_managers = [
        app.raiden.connection_manager_for_token_network(token_network_registry_address)
        for app in raiden_network
    ]

    unsaturated_connection_managers = connection_managers[:]
    exception = AssertionError("Unsaturated connection managers", unsaturated_connection_managers)
    with gevent.Timeout(120, exception):
        while unsaturated_connection_managers:
            for manager in unsaturated_connection_managers:
                if is_manager_saturated(manager, registry_address, token_address):
                    unsaturated_connection_managers.remove(manager)
            gevent.sleep(1)

    assert saturated_count(connection_managers, registry_address, token_address) == len(
        connection_managers
    )

    # ensure unpartitioned network
    for app in raiden_network:
        node_state = views.state_from_raiden(app.raiden)
        network_state = views.get_token_network_by_token_address(
            node_state, registry_address, token_address
        )
        assert network_state is not None
        for target in raiden_network:
            if target.raiden.address == app.raiden.address:
                continue
            _, routes, _ = routing.get_best_routes(
                chain_state=node_state,
                token_network_address=network_state.address,
                one_to_n_address=one_to_n_address,
                from_address=app.raiden.address,
                to_address=target.raiden.address,
                amount=PaymentAmount(1),
                previous_address=None,
                pfs_config=None,
                privkey=b"",  # not used if pfs is not configured
            )
            assert routes is not None

    # create a transfer to the leaving node, so we have a channel to settle
    for app in raiden_network:
        sender = app.raiden
        sender_channel = next(
            (
                channel_state
                for channel_state in RaidenAPI(sender).get_channel_list(
                    registry_address=registry_address, token_address=token_address
                )
                if channel_state.our_state.contract_balance > 0
                and channel_state.partner_state.contract_balance > 0
            ),
            None,
        )  # choose a fully funded channel from sender
        if sender_channel:
            break
    assert sender_channel
    registry_address = sender.default_registry.address

    receiver = next(
        app.raiden
        for app in raiden_network
        if app.raiden.address == sender_channel.partner_state.address
    )

    # assert there is a direct channel receiver -> sender (vv)
    receiver_channel = RaidenAPI(receiver).get_channel_list(
        registry_address=registry_address,
        token_address=token_address,
        partner_address=sender.address,
    )
    assert len(receiver_channel) == 1

    with gevent.Timeout(30, exception=ValueError("partner not reachable")):
        waiting.wait_for_healthy(sender, receiver.address, PaymentAmount(1))

    with watch_for_unlock_failures(*raiden_network):
        amount = PaymentAmount(1)
        RaidenAPI(sender).transfer_and_wait(
            registry_address, token_address, amount, receiver.address, transfer_timeout=10
        )

        with gevent.Timeout(
            30, exception=ValueError("timeout while waiting for incoming transaction")
        ):
            wait_for_transaction(receiver, registry_address, token_address, sender.address)

    # test `leave()` method
    connection_manager = connection_managers[0]

    timeout = (
        sender_channel.settle_timeout
        * estimate_blocktime(connection_manager.raiden.rpc_client)
        * 10
    )
    assert timeout > 0

    channels = views.list_channelstate_for_tokennetwork(
        chain_state=views.state_from_raiden(connection_manager.raiden),
        token_network_registry_address=registry_address,
        token_address=token_address,
    )
    channel_identifiers = [channel.identifier for channel in channels]

    with gevent.Timeout(timeout, exception=ValueError("timeout while waiting for leave")):
        # sender leaves the network
        RaidenAPI(sender).token_network_leave(registry_address, token_address)

    with gevent.Timeout(
        timeout, exception=ValueError(f"Channels didnt get settled after {timeout}")
    ):
        waiting.wait_for_settle(
            raiden=connection_manager.raiden,
            token_network_registry_address=registry_address,
            token_address=token_address,
            channel_ids=channel_identifiers,
            retry_timeout=0.1,
        )


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [4])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("settle_timeout", [10])
@pytest.mark.parametrize("reveal_timeout", [3])
def test_connect_does_not_open_channels_with_offline_nodes(raiden_network, token_addresses):
    """
    Test that using the connection manager to connect to a token network
    does not open channels with offline nodes

    Test for https://github.com/raiden-network/raiden/issues/5583
    """
    # pylint: disable=too-many-locals
    registry_address = raiden_network[0].raiden.default_registry.address
    token_address = token_addresses[0]
    app0, app1, _, _ = raiden_network
    offline_node = app0
    target_channels_num = 1

    # connect the first node - this will register the token and open the first channel
    # Since there is no other nodes available to connect to this call will do nothing more
    RaidenAPI(app0.raiden).token_network_connect(
        registry_address=registry_address,
        token_address=token_address,
        funds=TokenAmount(100),
        initial_channel_target=target_channels_num,
    )

    # First node will now go offline
    offline_node.stop()
    offline_node.raiden.greenlet.get()
    assert not offline_node.raiden

    # Call the connect endpoint for the second node
    RaidenAPI(app1.raiden).token_network_connect(
        registry_address=registry_address,
        token_address=token_address,
        funds=TokenAmount(100),
        initial_channel_target=target_channels_num,
    )
    token_network_registry_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(app1.raiden),
        token_network_registry_address=registry_address,
        token_address=token_address,
    )
    # and wait until connections are done. This should connect to an offline node
    # and create the first online discoverable
    manager = app1.raiden.connection_manager_for_token_network(token_network_registry_address)
    exception = AssertionError("Unsaturated connection manager", manager)
    with gevent.Timeout(120, exception):
        if not is_manager_saturated(manager, registry_address, token_address):
            gevent.sleep(1)

    # Call the connect endpoint for all but the two first nodes
    connect_greenlets = [
        gevent.spawn(
            RaidenAPI(app.raiden).token_network_connect,
            registry_address,
            token_address,
            100,
            target_channels_num,
        )
        for app in raiden_network[2:]
    ]
    gevent.wait(connect_greenlets)

    connection_managers = [
        app.raiden.connection_manager_for_token_network(token_network_registry_address)
        for app in raiden_network[2:]
    ]

    # Wait until channels are opened and connections are done
    unsaturated_connection_managers = connection_managers[2:]
    exception = AssertionError("Unsaturated connection managers", unsaturated_connection_managers)
    with gevent.Timeout(120, exception):
        while unsaturated_connection_managers:
            for manager in unsaturated_connection_managers:
                if is_manager_saturated(manager, registry_address, token_address):
                    unsaturated_connection_managers.remove(manager)
            gevent.sleep(1)

    assert saturated_count(connection_managers, registry_address, token_address) == len(
        connection_managers
    )

    for app in raiden_network[2:]:
        # ensure that we did not open a channel with the offline node
        node_state = views.state_from_raiden(app.raiden)
        network_state = views.get_token_network_by_token_address(
            node_state, registry_address, token_address
        )
        assert network_state is not None
        msg = "Each of the last 2 nodes should connect to 1 address"
        assert len(network_state.channelidentifiers_to_channels) == 1, msg
        for _, netchannel in network_state.channelidentifiers_to_channels.items():
            assert netchannel.partner_state.address != offline_node.raiden.address

    # Call the connect endpoint for all apps again to see this is handled fine.
    # This essentially checks that connecting to bootstrap/offline address again is not a problem
    for app in raiden_network[1:]:
        RaidenAPI(app.raiden).token_network_connect(
            registry_address=registry_address,
            token_address=token_address,
            funds=TokenAmount(100),
            initial_channel_target=target_channels_num,
        )
