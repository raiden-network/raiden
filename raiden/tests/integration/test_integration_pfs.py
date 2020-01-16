import pytest

from raiden.api.python import RaidenAPI
from raiden.app import App
from raiden.constants import DISCOVERY_DEFAULT_ROOM, PATH_FINDING_BROADCASTING_ROOM, RoutingMode
from raiden.messages.abstract import Message
from raiden.messages.path_finding_service import PFSCapacityUpdate, PFSFeeUpdate
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import (
    assert_succeeding_transfer_invariants,
    block_timeout_for_transfer_by_secrethash,
    transfer,
    wait_assert,
)
from raiden.tests.utils.transport import TestMatrixTransport
from raiden.transfer import views
from raiden.utils.typing import (
    List,
    PaymentAmount,
    PaymentID,
    TokenAddress,
    TokenAmount,
    WithdrawAmount,
)


def get_messages(app: App) -> List[Message]:
    assert isinstance(
        app.raiden.transport, TestMatrixTransport
    ), "Transport is not a `TestMatrixTransport`"

    return app.raiden.transport.broadcast_messages[PATH_FINDING_BROADCASTING_ROOM]


def reset_messages(app: App) -> None:
    assert isinstance(
        app.raiden.transport, TestMatrixTransport
    ), "Transport is not a `TestMatrixTransport`"

    app.raiden.transport.broadcast_messages[PATH_FINDING_BROADCASTING_ROOM] = []


@pytest.mark.skip(reason="flaky, see https://github.com/raiden-network/raiden/issues/5680")
@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize(
    "broadcast_rooms", [[DISCOVERY_DEFAULT_ROOM, PATH_FINDING_BROADCASTING_ROOM]]
)
@pytest.mark.parametrize("routing_mode", [RoutingMode.PFS])
def test_pfs_send_capacity_updates_on_deposit_and_withdraw(
    raiden_network: List[App], token_addresses: List[TokenAddress]
) -> None:
    """
    We need to test if PFSCapacityUpdates and PFSFeeUpdates are being
    sent after a deposit and withdraw.

    The nodes open a channel but do not deposit. After deposit and
    withdraw it is checked that the correct messages are sent.
    """
    app0, app1, app2 = raiden_network
    api0 = RaidenAPI(app0.raiden)
    api0.channel_open(
        token_address=token_addresses[0],
        registry_address=app0.raiden.default_registry.address,
        partner_address=app1.raiden.address,
    )

    # There should be no messages sent at channel opening
    assert len(get_messages(app0)) == 0
    assert len(get_messages(app1)) == 0
    assert len(get_messages(app2)) == 0

    api0.set_total_channel_deposit(
        token_address=token_addresses[0],
        registry_address=app0.raiden.default_registry.address,
        partner_address=app1.raiden.address,
        total_deposit=TokenAmount(10),
    )

    # We expect a PFSCapacityUpdate and a PFSFeeUpdate after the deposit
    messages0 = get_messages(app0)
    assert len(messages0) == 2
    assert len([x for x in messages0 if isinstance(x, PFSCapacityUpdate)]) == 1
    assert len([x for x in messages0 if isinstance(x, PFSFeeUpdate)]) == 1

    # We expect the same messages for the target
    messages1 = get_messages(app1)
    assert len(messages1) == 2
    assert len([x for x in messages1 if isinstance(x, PFSCapacityUpdate)]) == 1
    assert len([x for x in messages1 if isinstance(x, PFSFeeUpdate)]) == 1

    # Unrelated node should not send updates
    assert len(get_messages(app2)) == 0

    api0.set_total_channel_withdraw(
        token_address=token_addresses[0],
        registry_address=app0.raiden.default_registry.address,
        partner_address=app1.raiden.address,
        total_withdraw=WithdrawAmount(5),
    )

    # We expect a PFSCapacityUpdate and a PFSFeeUpdate after the withdraw
    messages0 = get_messages(app0)
    assert len(messages0) == 4
    assert len([x for x in messages0 if isinstance(x, PFSCapacityUpdate)]) == 2
    assert len([x for x in messages0 if isinstance(x, PFSFeeUpdate)]) == 2

    # We expect the same messages for the target
    messages1 = get_messages(app1)
    assert len(messages1) == 4
    assert len([x for x in messages1 if isinstance(x, PFSCapacityUpdate)]) == 2
    assert len([x for x in messages1 if isinstance(x, PFSFeeUpdate)]) == 2

    # Unrelated node should not send updates
    assert len(get_messages(app2)) == 0


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("broadcast_rooms", [[PATH_FINDING_BROADCASTING_ROOM]])
@pytest.mark.parametrize("routing_mode", [RoutingMode.PFS])
def test_pfs_send_capacity_updates_during_mediated_transfer(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait
):
    """
    Tests that PFSCapacityUpdates and PFSFeeUpdates are being
    sent during a mediated transfer.
    """
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    # There have been two PFSCapacityUpdates and two PFSFeeUpdates per channel per node
    assert len(get_messages(app0)) == 4
    # The mediator has two channels
    assert len(get_messages(app1)) == 8
    assert len(get_messages(app2)) == 4

    # Reset message lists for more understandable assertions
    reset_messages(app0)
    reset_messages(app1)
    reset_messages(app2)

    amount = PaymentAmount(10)
    secrethash = transfer(
        initiator_app=app0,
        target_app=app2,
        token_address=token_address,
        amount=amount,
        identifier=PaymentID(1),
        timeout=network_wait * number_of_nodes,
    )

    with block_timeout_for_transfer_by_secrethash(app1.raiden, secrethash):
        wait_assert(
            assert_succeeding_transfer_invariants,
            token_network_address,
            app0,
            deposit - amount,
            [],
            app1,
            deposit + amount,
            [],
        )

    with block_timeout_for_transfer_by_secrethash(app1.raiden, secrethash):
        wait_assert(
            assert_succeeding_transfer_invariants,
            token_network_address,
            app1,
            deposit - amount,
            [],
            app2,
            deposit + amount,
            [],
        )

    # Initiator: we expect one PFSCapacityUpdate when locking and one when unlocking
    messages0 = get_messages(app0)
    assert len(messages0) == 2
    assert len([x for x in messages0 if isinstance(x, PFSCapacityUpdate)]) == 2
    assert len([x for x in messages0 if isinstance(x, PFSFeeUpdate)]) == 0

    # Mediator:
    #   incoming channel: we expect one PFSCapacityUpdate when locking and one when unlocking
    #   outgoing channel: we expect one PFSCapacityUpdate when funds are unlocked
    messages1 = get_messages(app1)
    assert len(messages1) == 3
    assert len([x for x in messages1 if isinstance(x, PFSCapacityUpdate)]) == 3
    assert len([x for x in messages1 if isinstance(x, PFSFeeUpdate)]) == 0

    # Target: we expect one PFSCapacityUpdate when funds are unlocked
    messages2 = get_messages(app2)
    assert len(messages2) == 1
    assert len([x for x in messages2 if isinstance(x, PFSCapacityUpdate)]) == 1
    assert len([x for x in messages2 if isinstance(x, PFSFeeUpdate)]) == 0
