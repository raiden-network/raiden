# -*- coding: utf-8 -*-

"""
The test in this module uses the mocked raiden client to create blockchain events and
processes them. Additionally, it mocks the transport layer directly. It tests the
interaction of many moving parts - yet, it is currently really slow.
Therefore, usually mocked_integration should be used.
"""
from typing import List

import gevent
from raiden_contracts.contract_manager import ContractManager
from pathfinder.pathfinding_service import PathfindingService
from pathfinder.tests.fixtures import Mock
from raiden_libs.blockchain import BlockchainListener


def test_pfs_with_mocked_client(
    generate_raiden_clients,
    ethereum_tester,
    contracts_manager: ContractManager,
    blockchain_listener: BlockchainListener,
    channel_descriptions: List
):
    """Instantiates a pathfinding service with mocked transport,
    listening and processing blockchain events created by mocked Raiden clients"""
    clients = generate_raiden_clients(7)
    network_address = clients[0].contract.address
    pathfinding_service = PathfindingService(
        contracts_manager,
        transport=Mock(),
        token_network_listener=blockchain_listener,
        follow_networks=[network_address]
    )

    # there should be one token network registered
    assert len(pathfinding_service.token_networks) == 1

    token_network = pathfinding_service.token_networks[network_address]
    for (
        p1_index,
        p1_deposit,
        p1_transferred_amount,
        p1_fee,
        p2_index,
        p2_deposit,
        p2_transferred_amount,
        p2_fee
    ) in channel_descriptions:

        clients[p2_index].open_channel(clients[p1_index].address)
        clients[p1_index].deposit_to_channel(clients[p2_index].address, p1_deposit)
        clients[p2_index].deposit_to_channel(clients[p1_index].address, p2_deposit)
        ethereum_tester.mine_blocks(1)
        gevent.sleep(0)

    # there should be as many open channels as described
    assert len(token_network.channel_id_to_addresses.keys()) == len(channel_descriptions)

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
        p1_address, p2_address = token_network.channel_id_to_addresses[channel_id + 1]
        view1 = token_network.G[p1_address][p2_address]['view']
        view2 = token_network.G[p2_address][p1_address]['view']

        assert view1.deposit == p1_deposit
        assert view2.deposit == p2_deposit

    # check pathfinding
    paths = token_network.get_paths(clients[0].address, clients[3].address, 10, 5)
    assert len(paths) == 3
    assert paths[0]['path'] == [clients[0].address, clients[2].address, clients[3].address]
    assert paths[1]['path'] == [clients[0].address, clients[1].address, clients[4].address,
                                clients[3].address]
    assert paths[2]['path'] == [clients[0].address, clients[1].address, clients[2].address,
                                clients[3].address]

    # Fixme: implement channel close events with balance proofs
    # now close all channels
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
        pass

    # there should be no open channels
