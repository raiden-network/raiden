import random
from typing import List
from unittest.mock import Mock

import pytest
from eth_utils import to_checksum_address, encode_hex, keccak
from raiden_libs.contracts import ContractManager
from web3 import Web3
from web3.contract import Contract

from pathfinder.pathfinding_service import PathfindingService
from pathfinder.token_network import TokenNetwork


@pytest.fixture
def populate_token_networks(
    token_networks: List[TokenNetwork],
    token_network_contracts: List[Contract],
) -> None:

    for token_network in token_networks:
        # some random magic to add channels
        for channel_id in range(100):
            seed1, seed2 = random.sample(range(20), 2)

            p1 = to_checksum_address(encode_hex(keccak(seed1))[:42])
            p2 = to_checksum_address(encode_hex(keccak(seed2))[:42])

            token_network.handle_channel_opened_event(
                channel_id,
                p1,
                p2
            )

        # deposit to channels
        for channel_id in range(100):
            deposit1 = random.randint(0, 1000)
            deposit2 = random.randint(0, 1000)

            p1, p2 = token_network.channel_id_to_addresses[channel_id]
            token_network.handle_channel_new_deposit_event(
                channel_id,
                p1,
                deposit1
            )
            token_network.handle_channel_new_deposit_event(
                channel_id,
                p2,
                deposit2
            )
            # cuts negative values of probability distribution, fix with > 0 distribution
            token_network.update_fee(
                channel_id,
                abs(random.gauss(0.0002, 0.0001)),
                p1
            )
            token_network.update_fee(
                channel_id,
                abs(random.gauss(0.0002, 0.0001)),
                p2
            )


@pytest.fixture
def token_networks(
    token_network_contracts: List[Contract]
) -> List[TokenNetwork]:
    return [
        TokenNetwork(token_network_contract)
        for token_network_contract in token_network_contracts
    ]


@pytest.fixture
def pathfinding_service(
    web3: Web3,
    contract_manager: ContractManager,
    token_networks: List[TokenNetwork]
) -> PathfindingService:
    # TODO: replace with a pathfinding service that actually syncs with the tester chain.
    pathfinding_service = PathfindingService(
        web3,
        contract_manager,
        transport=Mock(),
        token_network_listener=Mock(),
        token_network_registry_listener=Mock()
    )
    pathfinding_service.token_networks = {
        token_network.address: token_network
        for token_network in token_networks
    }

    return pathfinding_service
