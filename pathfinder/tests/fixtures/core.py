from typing import List
from unittest.mock import Mock

import pytest
from raiden_libs.contracts import ContractManager
from web3 import Web3

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
