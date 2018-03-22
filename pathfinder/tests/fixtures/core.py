import random
from typing import List, Dict, Tuple
from unittest.mock import Mock

import pytest
from _pytest import monkeypatch
from eth_utils import to_checksum_address, encode_hex, keccak
from raiden_libs.contracts import ContractManager
from web3 import Web3

from pathfinder.contract.token_network_contract import TokenNetworkContract
from pathfinder.pathfinding_service import PathfindingService
from pathfinder.token_network import TokenNetwork
from pathfinder.utils.types import ChannelId, Address


@pytest.fixture
def populate_token_networks(
    token_networks: List[TokenNetwork],
    token_network_contracts: List[TokenNetworkContract],
    monkeypatch: monkeypatch
) -> None:

    def get_channel_deposits_patched(
        self: TokenNetworkContract,
        channel_id: ChannelId
    )-> Dict[Address, int]:

        random.seed(channel_id)
        deposit1 = random.randint(0, 1000)
        deposit2 = random.randint(0, 1000)
        participant1, participant2 = self.get_channel_participants(channel_id)
        return {participant1: deposit1, participant2: deposit2}

    def get_channel_participants_patched(
        self: TokenNetworkContract,
        channel_id: ChannelId
    ) -> Tuple[Address, Address]:
        random.seed(channel_id)
        seed1, seed2 = random.sample(range(100), 2)
        return (
          to_checksum_address(encode_hex(keccak(seed1))[:42]),
          to_checksum_address(encode_hex(keccak(seed2))[:42])
        )

    monkeypatch.setattr(
        TokenNetworkContract,
        'get_channel_participants',
        get_channel_participants_patched
    )
    monkeypatch.setattr(
        TokenNetworkContract,
        'get_channel_deposits',
        get_channel_deposits_patched
    )

    for token_network in token_networks:
        # some random magic to add channels
        for channel_id in range(1000):
            token_network.handle_channel_opened_event(channel_id)
            signer1, signer2 = token_network.token_network_contract.get_channel_participants(
                channel_id
            )
            # cuts negative values of probability distribution, fix with > 0 distribution
            token_network.update_fee(channel_id, abs(random.gauss(0.0002, 0.0001)), signer1)
            token_network.update_fee(channel_id, abs(random.gauss(0.0002, 0.0001)), signer2)


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
