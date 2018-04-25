# -*- coding: utf-8 -*-

"""
The test in this module uses the mocked raiden client to create blockchain events and
processes them. Additionally, it mocks the transport layer directly. It tests the
interaction of many moving parts - yet, it is currently really slow.
Therefore, usually mocked_integration should be used.
"""
import math
from typing import List

import gevent
from raiden_contracts.contract_manager import ContractManager
from raiden_libs.test.mocks.dummy_transport import DummyTransport

from pathfinder.pathfinding_service import PathfindingService
from raiden_libs.blockchain import BlockchainListener


def test_pfs_with_mocked_client(
    generate_raiden_clients,
    ethereum_tester,
    contracts_manager: ContractManager,
    blockchain_listener: BlockchainListener,
    channel_descriptions_case_1: List
):
    """Instantiates a pathfinding service with mocked transport,
    listening and processing blockchain events created by mocked Raiden clients"""
    clients = generate_raiden_clients(7)
    network_address = clients[0].contract.address
    pathfinding_service = PathfindingService(
        contracts_manager,
        transport=DummyTransport(),
        token_network_listener=blockchain_listener,
        follow_networks=[network_address]
    )

    pathfinding_service.start()
    token_network = pathfinding_service.token_networks[network_address]
    graph = token_network.G
    # there should be one token network registered
    assert len(pathfinding_service.token_networks) == 1

    for (
        p1_index,
        p1_deposit,
        p1_transferred_amount,
        p1_fee,
        p2_index,
        p2_deposit,
        p2_transferred_amount,
        p2_fee
    ) in channel_descriptions_case_1:

        clients[p2_index].open_channel(clients[p1_index].address)
        clients[p1_index].deposit_to_channel(clients[p2_index].address, p1_deposit)
        clients[p2_index].deposit_to_channel(clients[p1_index].address, p2_deposit)
    ethereum_tester.mine_blocks(1)
    gevent.sleep(0)

    # there should be as many open channels as described
    assert len(token_network.channel_id_to_addresses.keys()) == len(channel_descriptions_case_1)

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
    ) in enumerate(channel_descriptions_case_1):
        p1_address, p2_address = token_network.channel_id_to_addresses[channel_id + 1]
        view1 = graph[p1_address][p2_address]['view']
        view2 = graph[p2_address][p1_address]['view']

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
    # send some fee messages and check if they get processed correctly
    for (
        p1_index,
        p1_deposit,
        p1_transferred_amount,
        p1_fee,
        p2_index,
        p2_deposit,
        p2_transferred_amount,
        p2_fee
    ) in channel_descriptions_case_1:
        fee_info = clients[p2_index].get_fee_info(
            clients[p1_index].address,
            nonce=2,
            percentage_fee=0.11235813,
        )
        pathfinding_service.transport.transmit_data(fee_info.serialize_full())
        gevent.sleep(0)
        assert math.isclose(
                graph[clients[p2_index].address][clients[p1_index].address]['view'].percentage_fee,
                0.11235813
        )

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
    ) in enumerate(channel_descriptions_case_1):
        balance_proof = clients[p2_index].get_balance_proof(
            clients[p1_index].address, chain_id=2
        )
        clients[p2_index].close_channel(clients[p1_index].address, balance_proof)
    ethereum_tester.mine_blocks(1)
    gevent.sleep(0)

    # there should be no channels
    assert len(token_network.channel_id_to_addresses.keys()) == 0
