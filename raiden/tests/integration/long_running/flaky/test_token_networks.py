import pytest
import gevent

from raiden.api.python import RaidenAPI
from raiden.tests.utils.geth import wait_until_block
from raiden.transfer import views, channel
from raiden.transfer.state import CHANNEL_STATE_OPENED
from raiden import routing
from raiden import waiting


def wait_for_transaction(
    receiver,
    registry_address,
    token_address,
    sender_address,
):
    """Wait until a first transaction in a channel is received"""
    while True:
        receiver_channel = RaidenAPI(receiver).get_channel_list(
            registry_address=registry_address,
            token_address=token_address,
            partner_address=sender_address,
        )
        transaction_received = (
            len(receiver_channel) == 1 and
            receiver_channel[0].partner_state.balance_proof is not None
        )

        if transaction_received:
            break
        gevent.sleep(0.1)


def is_channel_open_and_funded(channel_state):
    return (
        channel.get_status(channel_state) == CHANNEL_STATE_OPENED and
        channel_state.our_state.contract_balance > 0 and
        channel_state.partner_state.contract_balance > 0
    )


def is_manager_saturated(connection_manager, registry_address, token_address):
    raiden = connection_manager.raiden
    open_channels = views.get_channelstate_filter(
        views.state_from_raiden(raiden),
        registry_address,
        token_address,
        lambda channel_state:
        (
            is_channel_open_and_funded(channel_state) and
            (
                channel_state.our_state.address == raiden.address or
                channel_state.partner_state.address == raiden.address
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


# TODO: add test scenarios for
# - subsequent `connect()` calls with different `funds` arguments
# - `connect()` calls with preexisting channels
# - Check if this test needs to be adapted for the matrix transport
#   layer when activating it again. It might as it depends on the
#   raiden_network fixture.
@pytest.mark.skip(reason='issue #1924')
@pytest.mark.parametrize('number_of_nodes', [6])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('settle_timeout', [6])
@pytest.mark.parametrize('reveal_timeout', [3])
def test_participant_selection(raiden_network, token_addresses, skip_if_tester):
    registry_address = raiden_network[0].raiden.default_registry.address

    # pylint: disable=too-many-locals
    token_address = token_addresses[0]

    # connect the first node (will register the token if necessary)
    RaidenAPI(raiden_network[0].raiden).token_network_connect(
        registry_address,
        token_address,
        100,
    )

    # connect the other nodes
    connect_greenlets = [
        gevent.spawn(
            RaidenAPI(app.raiden).token_network_connect,
            registry_address,
            token_address,
            100,
        )

        for app in raiden_network[1:]
    ]
    gevent.wait(connect_greenlets)

    token_network_registry_address = views.get_token_network_identifier_by_token_address(
        views.state_from_raiden(raiden_network[0].raiden),
        payment_network_id=registry_address,
        token_address=token_address,
    )
    connection_managers = [
        app.raiden.connection_manager_for_token_network(
            token_network_registry_address,
        ) for app in raiden_network
    ]

    unsaturated_connection_managers = connection_managers[:]
    with gevent.Timeout(
        120,
        AssertionError('Unsaturated connection managers', unsaturated_connection_managers),
    ):
        while unsaturated_connection_managers:
            for manager in unsaturated_connection_managers:
                if is_manager_saturated(manager, registry_address, token_address):
                    unsaturated_connection_managers.remove(manager)
            gevent.sleep(1)

    assert saturated_count(
        connection_managers,
        registry_address,
        token_address,
    ) == len(connection_managers)

    # ensure unpartitioned network
    for app in raiden_network:
        node_state = views.state_from_raiden(app.raiden)
        network_state = views.get_token_network_by_token_address(
            node_state,
            registry_address,
            token_address,
        )
        assert network_state is not None
        for target in raiden_network:
            if target.raiden.address == app.raiden.address:
                continue
            routes = routing.get_best_routes(
                node_state,
                network_state.address,
                app.raiden.address,
                target.raiden.address,
                1,
                None,
            )
            assert routes is not None

    # create a transfer to the leaving node, so we have a channel to settle
    sender = raiden_network[-1].raiden
    receiver = raiden_network[0].raiden

    registry_address = sender.default_registry.address
    # assert there is a direct channel receiver -> sender (vv)
    receiver_channel = RaidenAPI(receiver).get_channel_list(
        registry_address=registry_address,
        token_address=token_address,
        partner_address=sender.address,
    )
    assert len(receiver_channel) == 1
    receiver_channel = receiver_channel[0]

    # assert there is a direct channel sender -> receiver
    sender_channel = RaidenAPI(sender).get_channel_list(
        registry_address=registry_address,
        token_address=token_address,
        partner_address=receiver.address,
    )
    assert len(sender_channel) == 1
    sender_channel = sender_channel[0]

    exception = ValueError('partner not reachable')
    with gevent.Timeout(30, exception=exception):
        waiting.wait_for_healthy(sender, receiver.address, 1)

    amount = 1
    RaidenAPI(sender).transfer_and_wait(
        registry_address,
        token_address,
        amount,
        receiver.address,
        transfer_timeout=10,
    )

    exception = ValueError('timeout while waiting for incoming transaction')
    with gevent.Timeout(30, exception=exception):
        wait_for_transaction(
            receiver,
            registry_address,
            token_address,
            sender.address,
        )

    # test `leave()` method
    connection_manager = connection_managers[0]

    timeout = (
        sender_channel.settle_timeout *
        connection_manager.raiden.chain.estimate_blocktime() *
        10
    )

    assert timeout > 0
    exception = ValueError('timeout while waiting for leave')
    with gevent.Timeout(timeout, exception=exception):
        RaidenAPI(raiden_network[0].raiden).token_network_leave(
            registry_address,
            token_address,
        )

    before_block = connection_manager.raiden.chain.block_number()
    wait_blocks = sender_channel.settle_timeout + 10
    # wait until both chains are synced?
    wait_until_block(
        connection_manager.raiden.chain,
        before_block + wait_blocks,
    )
    wait_until_block(
        receiver.chain,
        before_block + wait_blocks,
    )
    receiver_channel = RaidenAPI(receiver).get_channel_list(
        registry_address=registry_address,
        token_address=token_address,
        partner_address=sender.address,
    )
    assert receiver_channel[0].settle_transaction is not None
