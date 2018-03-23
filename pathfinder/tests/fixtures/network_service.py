import random
from typing import List
from unittest.mock import Mock
import pytest
from coincurve import PrivateKey
from eth_utils import to_checksum_address, remove_0x_prefix
from raiden_libs.contracts import ContractManager
from raiden_libs.utils import public_key_to_address
from web3 import Web3
from web3.contract import Contract
from pathfinder.pathfinding_service import PathfindingService
from pathfinder.tests.config import NUMBER_OF_CHANNELS
from pathfinder.token_network import TokenNetwork
from pathfinder.utils.types import Address


@pytest.fixture
def populate_token_networks(
        token_networks: List[TokenNetwork],
        token_network_contracts: List[Contract],
        addresses: List[Address],
        private_keys: List[str],
) -> None:
    random.seed(NUMBER_OF_CHANNELS)
    # seed for pseudo-randomness from config constant, that changes from time to time
    for token_network in token_networks:
        for channel_id in range(NUMBER_OF_CHANNELS):
            seed1, seed2 = random.sample(private_keys, 2)
            private_key_ecdsa1 = PrivateKey.from_hex(remove_0x_prefix(seed1))
            private_key_ecdsa2 = PrivateKey.from_hex(remove_0x_prefix(seed2))
            address1 = to_checksum_address(public_key_to_address(private_key_ecdsa1.public_key))
            address2 = to_checksum_address(public_key_to_address(private_key_ecdsa2.public_key))
            fee1 = str(abs(random.gauss(0.0002, 0.0001))).encode()
            fee2 = str(abs(random.gauss(0.0002, 0.0001))).encode()
            signature1 = private_key_ecdsa1.sign_recoverable(fee1)
            signature2 = private_key_ecdsa2.sign_recoverable(fee2)
            token_network.handle_channel_opened_event(
                channel_id,
                address1,
                address2
            )

            # deposit to channels
            deposit1, deposit2 = random.sample(range(1000), 2)
            address1, address2 = token_network.channel_id_to_addresses[channel_id]
            token_network.handle_channel_new_deposit_event(
                channel_id,
                address1,
                deposit1
            )
            token_network.handle_channel_new_deposit_event(
                channel_id,
                address2,
                deposit2
            )
            # cuts negative values of probability distribution, fix with > 0 distribution

            token_network.update_fee(
                channel_id,
                fee1,
                signature1
            )
            token_network.update_fee(
                channel_id,
                fee2,
                signature2
            )


@pytest.fixture
def token_networks(token_network_contracts: List[Contract]) -> List[TokenNetwork]:
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
