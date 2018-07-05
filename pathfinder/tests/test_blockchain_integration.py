"""
The test in this module uses the mocked raiden client to create blockchain events and
processes them. Additionally, it mocks the transport layer directly. It tests the
interaction of many moving parts - yet, it is currently really slow.
Therefore, usually mocked_integration should be used.
"""
from typing import List

import gevent
from raiden_contracts.contract_manager import ContractManager
from raiden_libs.test.mocks.dummy_transport import DummyTransport
from raiden_libs.blockchain import BlockchainListener

from pathfinder.pathfinding_service import PathfindingService
from pathfinder.model import ChannelView


def test_pfs_with_mocked_client(
    web3,
    ethereum_tester,
    contracts_manager: ContractManager,
    blockchain_listener: BlockchainListener,
    channel_descriptions_case_1: List,
    generate_dummy_network,
    get_random_address
):
    """Instantiates a DummyNetwork some Mockclients and the pathfinding service exchange messages
    over. Mocks blockchain events to setup a token network with a given topology, specified in
    the channel_description fixture. Tests all PFS methods w.r.t. to that topology"""

    network, clients = generate_dummy_network(7)
    pfs_address = get_random_address()
    pfs_transport = DummyTransport(network)
    network.add_transport(pfs_address, pfs_transport)
    token_network_address = clients[0].contract.address

    pfs = PathfindingService(
        contracts_manager,
        transport=pfs_transport,
        chain_id=int(web3.net.version),
        token_network_listener=blockchain_listener,
        follow_networks=[token_network_address]
    )

    token_network = pfs.token_networks[token_network_address]
    graph = token_network.G

    # there should be one token network registered
    assert len(pfs.token_networks) == 1

    channel_identifiers = []

    for index, (
        p1_index,
        p1_deposit,
        p1_transferred_amount,
        p1_fee,
        p2_index,
        p2_deposit,
        p2_transferred_amount,
        p2_fee
    ) in enumerate(channel_descriptions_case_1):
        # order is important here because we check order later
        channel_identifier = clients[p1_index].open_channel(clients[p2_index].address)
        channel_identifiers.append(channel_identifier)

        clients[p1_index].deposit_to_channel(clients[p2_index].address, p1_deposit)
        clients[p2_index].deposit_to_channel(clients[p1_index].address, p2_deposit)
        gevent.sleep()

        balance_proof_p1 = clients[p1_index].get_balance_proof(
            clients[p2_index].address,
            nonce=index + 1,
            transferred_amount=p1_transferred_amount,
            locked_amount=0,
            locksroot='0x%064x' % 0,
            additional_hash='0x%064x' % 23
        )
        balance_proof_p2 = clients[p2_index].get_balance_proof(
            clients[p1_index].address,
            nonce=index + 1,
            transferred_amount=p2_transferred_amount,
            locked_amount=0,
            locksroot='0x%064x' % 0,
            additional_hash='0x%064x' % 23
        )

        clients[p1_index].transport.send_message(
            balance_proof_p1.serialize_full(),
            pfs_address
        )

        clients[p2_index].transport.send_message(
            balance_proof_p2.serialize_full(),
            pfs_address
        )

    ethereum_tester.mine_blocks(1)
    gevent.sleep(0)

    # there should be as many open channels as described
    assert len(token_network.channel_id_to_addresses.keys()) == len(channel_descriptions_case_1)

    # check that deposits and transfers got registered
    for index, (
        p1_index,
        p1_deposit,
        p1_transferred_amount,
        p1_fee,
        p2_index,
        p2_deposit,
        p2_transferred_amount,
        p2_fee
    ) in enumerate(channel_descriptions_case_1):
        channel_identifier = channel_identifiers[index]
        p1_address, p2_address = token_network.channel_id_to_addresses[channel_identifier]
        view1: ChannelView = graph[p1_address][p2_address]['view']
        view2: ChannelView = graph[p2_address][p1_address]['view']

        assert view1.deposit == p1_deposit
        assert view2.deposit == p2_deposit

        assert view1.transferred_amount == p1_transferred_amount
        assert view2.transferred_amount == p2_transferred_amount

    # send some fee messages and check if they get processed correctly
    for index, (
        p1_index,
        p1_deposit,
        p1_transferred_amount,
        p1_fee,
        p2_index,
        p2_deposit,
        p2_transferred_amount,
        p2_fee
    ) in enumerate(channel_descriptions_case_1):
        client1 = clients[p1_index]
        client2 = clients[p2_index]
        fee_info_p1 = client1.get_fee_info(
            client2.address,
            nonce=index + 1,
            relative_fee=p1_fee,
        )
        fee_info_p2 = client2.get_fee_info(
            client1.address,
            nonce=index + 1,
            relative_fee=p2_fee,
        )

        clients[p1_index].transport.send_message(
            fee_info_p1.serialize_full(),
            pfs_address
        )

        clients[p2_index].transport.send_message(
            fee_info_p2.serialize_full(),
            pfs_address
        )

        assert graph[client1.address][client2.address]['view'].relative_fee == p1_fee
        assert graph[client2.address][client1.address]['view'].relative_fee == p2_fee

    # send a path paths_request from a client to the PFS

    paths_request = clients[0].request_paths(
        clients[3].address,
        value=10,
        num_paths=5,
        chain_id=1,
        nonce=1,
    )

    clients[0].transport.send_message(paths_request, pfs_address)

    # This is implicitly testing the following steps:
    # PathRequest arrives at PFS
    # PFS.get_paths gives correct answer
    # PFS.paths_reply response is triggered, send over transport back to the requesting client
    # Requesting client is receiving the reply

    paths = clients[0].paths_and_fees

    assert paths[0]['path'] == [clients[0].address, clients[1].address, clients[2].address,
                                clients[3].address]
    assert paths[1]['path'] == [clients[0].address, clients[1].address, clients[4].address,
                                clients[3].address]

    # now close all channels
    for index, (
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
            clients[p1_index].address,
            nonce=1,
            transferred_amount=0,
            locked_amount=0,
            locksroot='0x%064x' % 0,
            additional_hash='0x%064x' % 1
        )
        clients[p1_index].close_channel(clients[p2_index].address, balance_proof)

    ethereum_tester.mine_blocks(1)
    gevent.sleep(0)

    # there should be no channels
    assert len(token_network.channel_id_to_addresses.keys()) == 0
