from typing import List
from unittest.mock import Mock

import pytest

from pathfinder.blockchain import BlockchainMonitor
from pathfinder.contract.token_network_contract import TokenNetworkContract
from pathfinder.pathfinding_service import PathfindingService
from pathfinder.token_network import TokenNetwork


@pytest.fixture
def token_networks(token_network_contracts: List[TokenNetworkContract]) -> List[TokenNetwork]:
    return [
        TokenNetwork(token_network_contract)
        for token_network_contract in token_network_contracts
    ]


@pytest.fixture
def pathfinding_service(token_networks: List[TokenNetwork]) -> PathfindingService:
    # TODO: replace with a pathfinding service that actually syncs with the tester chain.
    blockchain = BlockchainMonitor()
    pathfinding_service = PathfindingService(
        transport=Mock(),
        blockchain=blockchain
    )
    pathfinding_service.token_networks = {
        token_network.address: token_network
        for token_network in token_networks
    }

    return pathfinding_service
