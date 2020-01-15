from unittest.mock import MagicMock

import pytest

from raiden.api.python import RaidenAPI
from raiden.app import App
from raiden.constants import DISCOVERY_DEFAULT_ROOM, PATH_FINDING_BROADCASTING_ROOM, RoutingMode
from raiden.network.transport.matrix import make_room_alias
from raiden.network.transport.matrix.client import Room
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.transfer import (
    assert_succeeding_transfer_invariants,
    block_timeout_for_transfer_by_secrethash,
    transfer,
    wait_assert,
)
from raiden.transfer import views
from raiden.utils.typing import (
    List,
    PaymentAmount,
    PaymentID,
    TokenAddress,
    TokenAmount,
    WithdrawAmount,
)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize(
    "broadcast_rooms", [[DISCOVERY_DEFAULT_ROOM, PATH_FINDING_BROADCASTING_ROOM]]
)
@pytest.mark.parametrize("routing_mode", [RoutingMode.PFS])
def test_pfs_send_capacity_updates_on_deposit_and_withdraw(
    raiden_network: List[App], token_addresses: List[TokenAddress]
) -> None:
    # We need to test if PFSCapacityUpdates and PFSFeeUpdates are being
    # sent after a deposit and withdraw.
    # Therefore, we create two Raiden nodes app0 and app1.
    # The nodes open a channel but do not deposit
    # a pfs matrix room is mocked to see what is sent to it

    app0, app1 = raiden_network
    transport0 = app0.raiden.transport

    pfs_room_name = make_room_alias(transport0.chain_id, PATH_FINDING_BROADCASTING_ROOM)
    pfs_room = transport0._broadcast_rooms.get(pfs_room_name)
    # need to assert for mypy that pfs_room is not None
    assert isinstance(pfs_room, Room)
    pfs_room.send_text = MagicMock(spec=pfs_room.send_text)

    api0 = RaidenAPI(app0.raiden)

    api0.channel_open(
        token_address=token_addresses[0],
        registry_address=app0.raiden.default_registry.address,
        partner_address=app1.raiden.address,
    )

    # the room should not have been called at channel opening
    assert pfs_room.send_text.call_count == 0

    api0.set_total_channel_deposit(
        token_address=token_addresses[0],
        registry_address=app0.raiden.default_registry.address,
        partner_address=app1.raiden.address,
        total_deposit=TokenAmount(10),
    )

    # now we expect the room to be called the 1st time with a PFSCapacityUpdate
    # and a PFSFeeUpdate after the deposit
    assert "PFSCapacityUpdate" in str(pfs_room.send_text.call_args_list[0])
    assert "PFSFeeUpdate" in str(pfs_room.send_text.call_args_list[0])

    api0.set_total_channel_withdraw(
        token_address=token_addresses[0],
        registry_address=app0.raiden.default_registry.address,
        partner_address=app1.raiden.address,
        total_withdraw=WithdrawAmount(5),
    )

    # now we expect the room to be called the 2nd time with a PFSCapacityUpdate
    # after the withdraw
    assert "PFSCapacityUpdate" in str(pfs_room.send_text.call_args_list[1])
    assert "PFSFeeUpdate" in str(pfs_room.send_text.call_args_list[1])


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("broadcast_rooms", [[PATH_FINDING_BROADCASTING_ROOM]])
@pytest.mark.parametrize("routing_mode", [RoutingMode.PFS])
def test_pfs_send_capacity_updates_during_mediated_transfer(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait
):
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    chain_id = app0.raiden.rpc_client.chain_id
    pfs_room_name = make_room_alias(chain_id, PATH_FINDING_BROADCASTING_ROOM)

    # Mock send_text on the PFS room
    pfs_rooms: List[Room] = []
    for app in [app0, app1]:
        transport = app.raiden.transport
        pfs_room = transport._broadcast_rooms.get(pfs_room_name)
        # need to assert for mypy that pfs_room0 is not None
        assert isinstance(pfs_room, Room)
        pfs_room.send_text = MagicMock(spec=pfs_room.send_text)
        pfs_rooms.append(pfs_room)

    amount = PaymentAmount(10)
    secrethash = transfer(
        initiator_app=app0,
        target_app=app1,
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

    # Initiator: we expect one PFSCapacityUpdate when locking and one when unlocking
    assert pfs_rooms[0].send_text.call_count == 2
    assert "PFSCapacityUpdate" in str(pfs_rooms[0].send_text.call_args_list[0])

    # Target: we expect one PFSCapacityUpdate when funds are unlocked
    assert pfs_rooms[1].send_text.call_count == 1
    assert "PFSCapacityUpdate" in str(pfs_rooms[1].send_text.call_args_list[0])
