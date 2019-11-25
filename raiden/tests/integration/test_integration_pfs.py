from unittest.mock import MagicMock

import pytest

from raiden.api.python import RaidenAPI
from raiden.app import App
from raiden.constants import DISCOVERY_DEFAULT_ROOM, PATH_FINDING_BROADCASTING_ROOM, RoutingMode
from raiden.network.transport.matrix import make_room_alias
from raiden.network.transport.matrix.client import Room
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.utils.typing import List, TokenAddress, TokenAmount, WithdrawAmount


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
    # we need to test if CapacityUpdates are sent after a deposit and a withdraw
    # therefore, we create two Raiden nodes app0 and app1
    # the nodes open a channel but do not deposit
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
    # after the deposit
    assert pfs_room.send_text.call_count == 1
    assert "PFSCapacityUpdate" in str(pfs_room.send_text.call_args_list[0])

    api0.set_total_channel_withdraw(
        token_address=token_addresses[0],
        registry_address=app0.raiden.default_registry.address,
        partner_address=app1.raiden.address,
        total_withdraw=WithdrawAmount(5),
    )

    # now we expect the room to be called the 2nd time with a PFSCapacityUpdate
    # after the withdraw
    assert pfs_room.send_text.call_count == 2
    assert "PFSCapacityUpdate" in str(pfs_room.send_text.call_args_list[1])
