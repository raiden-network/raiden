# -*- coding: utf-8 -*-
"""
The tests in this module mock events creation by using a mock blockchain listener.

This makes them a lot faster than using full blockchain based approach and they should
be used most of the time to keep test times short.
"""
from typing import List

from unittest.mock import Mock
from web3 import Web3
from raiden_contracts.contract_manager import ContractManager
from raiden_libs.test.mocks.blockchain import BlockchainListenerMock

from pathfinder.model.token_network import TokenNetwork
from pathfinder.pathfinding_service import PathfindingService
from pathfinder.utils.types import Address


def test_pfs_with_mocked_events(
    token_networks: List[TokenNetwork],  # just used for addresses
    addresses: List[Address],
    pathfinding_service_mocked_listeners: PathfindingService
):
    network_listener = pathfinding_service_mocked_listeners.token_network_listener
    registry_listener = pathfinding_service_mocked_listeners.token_network_registry_listener

    token_network_address = token_networks[0].address

    # this is a new pathfinding service, there should be no token networks registered
    assert len(pathfinding_service_mocked_listeners.token_networks.keys()) == 0

    # emit a TokenNetworkCreated event
    registry_listener.emit_event(dict(
        name='TokenNetworkCreated',
        args=dict(
            token_network_address=token_network_address
        )
    ))

    # now there should be a token network registered
    assert token_network_address in pathfinding_service_mocked_listeners.token_networks
    token_network = pathfinding_service_mocked_listeners.token_networks[token_network_address]

    # Now initialize some channels in this network.
    # The tuples in channel_descriptions define the following:
    # (
    #     p1_index,
    #     p1_deposit,
    #     p1_transferred_amount,
    #     p1_fee,
    #     p2_index,
    #     p2_deposit,
    #     p2_transferred_amount,
    #     p2_fee
    # )
    # Topology:
    #       /-------------\
    # 0 -- 1 -- 2 -- 3 -- 4    5 -- 6
    #  \-------/

    channel_descriptions = [
        (0, 100,  20, 0.0010, 1,  50,  10, 0.0015),  # capacities  90 --  60
        (1,  40,  10, 0.0008, 2, 130, 100, 0.0012),  # capacities 130 --  40
        (2,  90,  10, 0.0007, 3,   0,   0, 0.0010),  # capacities  80 --  10
        (3,  50,  20, 0.0011, 4,  50,  20, 0.0011),  # capacities  50 --  50
        (0,  40,  40, 0.0015, 2,  80,   0, 0.0025),  # capacities   0 -- 120
        (1,  30,  10, 0.0100, 4,  40,  15, 0.0018),  # capacities  35 --  35
        (5, 500, 900, 0.0030, 6, 750, 950, 0.0040),  # capacities 550 -- 700
    ]
    for channel_id, (
        p1_index,
        p1_deposit,
        p1_transferred_amount,
        p1_fee,
        p2_index,
        p2_deposit,
        p2_transferred_amount,
        p2_fee
    ) in enumerate(channel_descriptions):
        network_listener.emit_event(dict(
            address=token_network_address,
            name='ChannelOpened',
            args=dict(
                channel_identifier=channel_id,
                participant1=addresses[p1_index],
                participant2=addresses[p2_index]
            )
        ))

        network_listener.emit_event(dict(
            address=token_network_address,
            name='ChannelNewDeposit',
            args=dict(
                channel_identifier=channel_id,
                participant=addresses[p1_index],
                total_deposit=p1_deposit
            )
        ))

        network_listener.emit_event(dict(
            address=token_network_address,
            name='ChannelNewDeposit',
            args=dict(
                channel_identifier=channel_id,
                participant=addresses[p2_index],
                total_deposit=p2_deposit
            )
        ))

    # now there should be seven channels
    assert len(token_network.channel_id_to_addresses.keys()) == 7

    # check that deposits got registered
    for channel_id, (
        p1_index,
        p1_deposit,
        p1_transferred_amount,
        p1_fee,
        p2_index,
        p2_deposit,
        p2_transferred_amount,
        p2_fee
    ) in enumerate(channel_descriptions):
        p1, p2 = token_network.channel_id_to_addresses[channel_id]
        assert p1 == addresses[p1_index]
        assert p2 == addresses[p2_index]

        view1 = token_network.G[p1][p2]['view']
        view2 = token_network.G[p2][p1]['view']

        assert view1.deposit == p1_deposit
        assert view2.deposit == p2_deposit

    # check pathfinding
    paths = token_network.get_paths(addresses[0], addresses[3], 10, 5)
    assert len(paths) == 3
    assert paths[0]['path'] == [addresses[0], addresses[2], addresses[3]]
    assert paths[1]['path'] == [addresses[0], addresses[1], addresses[4], addresses[3]]
    assert paths[2]['path'] == [addresses[0], addresses[1], addresses[2], addresses[3]]

    # wow close all channels
    for channel_id, (
        p1_index,
        p1_deposit,
        p1_transferred_amount,
        p1_fee,
        p2_index,
        p2_deposit,
        p2_transferred_amount,
        p2_fee
    ) in enumerate(channel_descriptions):
        network_listener.emit_event(dict(
            address=token_network_address,
            name='ChannelClosed',
            args=dict(
                channel_identifier=channel_id,
                closing_participant=addresses[p1_index]
            )
        ))

    # there should be no channels
    assert len(token_network.channel_id_to_addresses.keys()) == 0


def test_pfs_idempotency_of_channel_openings(
    token_networks: List[TokenNetwork],  # just used for addresses
    addresses: List[Address],
    pathfinding_service_mocked_listeners: PathfindingService
):
    network_listener = pathfinding_service_mocked_listeners.token_network_listener
    registry_listener = pathfinding_service_mocked_listeners.token_network_registry_listener

    token_network_address = token_networks[0].address

    # this is a new Pathfinding Service, there should be no token networks registered
    assert len(pathfinding_service_mocked_listeners.token_networks.keys()) == 0

    # emit a TokenNetworkCreated event
    registry_listener.emit_event(dict(
        name='TokenNetworkCreated',
        args=dict(
            token_network_address=token_network_address
        )
    ))

    # now there should be a token network registered
    assert token_network_address in pathfinding_service_mocked_listeners.token_networks
    token_network = pathfinding_service_mocked_listeners.token_networks[token_network_address]

    # create same channel 5 times
    for _ in range(5):
        network_listener.emit_event(dict(
            address=token_network_address,
            name='ChannelOpened',
            args=dict(
                channel_identifier=1,
                participant1=addresses[0],
                participant2=addresses[1]
            )
        ))

    # there should only be one channel
    assert len(token_network.channel_id_to_addresses.keys()) == 1

    # now close the channel
    network_listener.emit_event(dict(
        address=token_network_address,
        name='ChannelClosed',
        args=dict(
            channel_identifier=1,
            closing_participant=addresses[0]
        )
    ))

    # there should be no channels
    assert len(token_network.channel_id_to_addresses.keys()) == 0


def test_pfs_multiple_channels_for_two_participants_opened(
    token_networks: List[TokenNetwork],  # just used for addresses
    addresses: List[Address],
    pathfinding_service_mocked_listeners: PathfindingService
):
    network_listener = pathfinding_service_mocked_listeners.token_network_listener
    registry_listener = pathfinding_service_mocked_listeners.token_network_registry_listener

    token_network_address = token_networks[0].address

    # this is a new Pathfinding Service, there should be no token networks registered
    assert len(pathfinding_service_mocked_listeners.token_networks.keys()) == 0

    # emit a TokenNetworkCreated event
    registry_listener.emit_event(dict(
        name='TokenNetworkCreated',
        args=dict(
            token_network_address=token_network_address
        )
    ))

    # now there should be a token network registered
    assert token_network_address in pathfinding_service_mocked_listeners.token_networks
    token_network = pathfinding_service_mocked_listeners.token_networks[token_network_address]

    # create a channel
    network_listener.emit_event(dict(
        address=token_network_address,
        name='ChannelOpened',
        args=dict(
            channel_identifier=1,
            participant1=addresses[0],
            participant2=addresses[1]
        )
    ))

    # create a channel
    network_listener.emit_event(dict(
        address=token_network_address,
        name='ChannelOpened',
        args=dict(
            channel_identifier=2,
            participant1=addresses[1],
            participant2=addresses[0]
        )
    ))

    # now there should be two channels
    assert len(token_network.channel_id_to_addresses.keys()) == 2

    # now close one channel
    network_listener.emit_event(dict(
        address=token_network_address,
        name='ChannelClosed',
        args=dict(
            channel_identifier=1,
            closing_participant=addresses[0]
        )
    ))

    # there should be one channel left
    assert len(token_network.channel_id_to_addresses.keys()) == 1


def test_pfs_events_from_unknown_token_network_ignored(
    token_networks: List[TokenNetwork],  # just used for addresses
    addresses: List[Address],
    pathfinding_service_mocked_listeners: PathfindingService
):
    network_listener = pathfinding_service_mocked_listeners.token_network_listener
    registry_listener = pathfinding_service_mocked_listeners.token_network_registry_listener

    token_network_address = token_networks[0].address

    # this is a new Pathfinding Service, there should be no token networks registered
    assert len(pathfinding_service_mocked_listeners.token_networks.keys()) == 0

    # emit a TokenNetworkCreated event
    registry_listener.emit_event(dict(
        name='TokenNetworkCreated',
        args=dict(
            token_network_address=token_network_address
        )
    ))

    # now there should be a token network registered
    assert token_network_address in pathfinding_service_mocked_listeners.token_networks
    token_network = pathfinding_service_mocked_listeners.token_networks[token_network_address]

    # create a channel for the network
    network_listener.emit_event(dict(
        address=token_network_address,
        name='ChannelOpened',
        args=dict(
            channel_identifier=1,
            participant1=addresses[0],
            participant2=addresses[1]
        )
    ))

    # now there should be a channel
    assert len(token_network.channel_id_to_addresses.keys()) == 1

    # now create a channel on a different token network
    network_listener.emit_event(dict(
        address=token_networks[1].address,
        name='ChannelOpened',
        args=dict(
            channel_identifier=1,
            participant1=addresses[0],
            participant2=addresses[1]
        )
    ))

    # there should still be one channel
    assert len(token_network.channel_id_to_addresses.keys()) == 1


def test_pfs_follow_networks_has_precedence_over_listener(
    web3: Web3,
    contracts_manager: ContractManager,
    token_networks: List[TokenNetwork]
):
    network_listener = BlockchainListenerMock()
    registry_listener = BlockchainListenerMock()

    pathfinding_service = PathfindingService(
        web3,
        contracts_manager,
        transport=Mock(),
        token_network_listener=network_listener,
        follow_networks=[token_networks[0].address, token_networks[1].address],
        token_network_registry_listener=registry_listener
    )

    token_network_address = token_networks[2].address

    # two networks set in follow_networks, so there should be two networks
    assert len(pathfinding_service.token_networks.keys()) == 2

    # emit a TokenNetworkCreated event
    registry_listener.emit_event(dict(
        name='TokenNetworkCreated',
        args=dict(
            token_network_address=token_network_address
        )
    ))

    # this shouldn't change
    assert len(pathfinding_service.token_networks.keys()) == 2
