"""
The test in this module uses the mocked raiden client to create blockchain events and
processes them. Additionally, it mocks the transport layer directly. It tests the
interaction of many moving parts - yet, it is currently really slow.
Therefore, usually mocked_integration should be used.
"""
from typing import List

import gevent
import pytest

from pathfinder.model import ChannelView
from pathfinder.pathfinding_service import PathfindingService
from raiden_contracts.contract_manager import ContractManager


@pytest.mark.skip(reason="Needs more work")
def test_pfs_with_mocked_client(
    web3,
    ethereum_tester,
    contracts_manager: ContractManager,
    token_network_registry_contract,
    channel_descriptions_case_1: List,
    generate_raiden_clients,
    get_random_address,
):
    """Instantiates a DummyNetwork some Mockclients and the pathfinding service exchange messages
    over. Mocks blockchain events to setup a token network with a given topology, specified in
    the channel_description fixture. Tests all PFS methods w.r.t. to that topology"""

    print(token_network_registry_contract.address)
    clients = generate_raiden_clients(7)
    token_network_address = clients[0].contract.address

    pfs = PathfindingService(
        web3=web3,
        contract_manager=contracts_manager,
        registry_address=token_network_registry_contract.address,
    )

    # Need a context switch for the network to be picked up
    gevent.sleep(0)

    token_network = pfs.token_networks[token_network_address]
    graph = token_network.G

    # there should be one token network registered
    assert len(pfs.token_networks) == 1

    channel_identifiers = []

    for (
        p1_index,
        p1_deposit,
        _p1_transferred_amount,
        _p1_fee,
        p2_index,
        p2_deposit,
        _p2_transferred_amount,
        _p2_fee,
    ) in channel_descriptions_case_1:
        # order is important here because we check order later
        channel_identifier = clients[p1_index].open_channel(clients[p2_index].address)
        channel_identifiers.append(channel_identifier)

        clients[p1_index].deposit_to_channel(clients[p2_index].address, p1_deposit)
        clients[p2_index].deposit_to_channel(clients[p1_index].address, p2_deposit)
        gevent.sleep()

    ethereum_tester.mine_blocks(1)
    gevent.sleep(0)

    # there should be as many open channels as described
    assert len(token_network.channel_id_to_addresses.keys()) == len(channel_descriptions_case_1)

    # check that deposits and transfers got registered
    for index, (
        _p1_index,
        p1_deposit,
        _p1_transferred_amount,
        _p1_fee,
        _p2_index,
        p2_deposit,
        _p2_transferred_amount,
        _p2_fee,
    ) in enumerate(channel_descriptions_case_1):
        channel_identifier = channel_identifiers[index]
        p1_address, p2_address = token_network.channel_id_to_addresses[channel_identifier]
        view1: ChannelView = graph[p1_address][p2_address]['view']
        view2: ChannelView = graph[p2_address][p1_address]['view']

        assert view1.deposit == p1_deposit
        assert view2.deposit == p2_deposit

    # now close all channels
    for (
        p1_index,
        _p1_deposit,
        _p1_transferred_amount,
        _p1_fee,
        p2_index,
        _p2_deposit,
        _p2_transferred_amount,
        _p2_fee,
    ) in channel_descriptions_case_1:
        balance_proof = clients[p2_index].get_balance_proof(
            clients[p1_index].address,
            nonce=1,
            transferred_amount=0,
            locked_amount=0,
            locksroot='0x%064x' % 0,
            additional_hash='0x%064x' % 1,
        )
        clients[p1_index].close_channel(clients[p2_index].address, balance_proof)

    ethereum_tester.mine_blocks(1)
    gevent.sleep(0)

    # there should be no channels
    assert len(token_network.channel_id_to_addresses.keys()) == 0
