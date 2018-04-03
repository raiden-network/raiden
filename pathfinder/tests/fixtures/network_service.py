import random
from typing import List
from unittest.mock import Mock
import pytest
from coincurve import PrivateKey
from eth_utils import remove_0x_prefix
from raiden_libs.contracts import ContractManager
from raiden_libs.utils import EMPTY_MERKLE_ROOT, private_key_to_address
from web3 import Web3
from web3.contract import Contract

from pathfinder.model.balance_proof import BalanceProof
from pathfinder.pathfinding_service import PathfindingService
from pathfinder.tests.config import NUMBER_OF_CHANNELS
from pathfinder.token_network import TokenNetwork
from pathfinder.utils.types import Address


@pytest.fixture
def token_networks(token_network_contracts: List[Contract]) -> List[TokenNetwork]:
    return [
        TokenNetwork(token_network_contract)
        for token_network_contract in token_network_contracts
    ]


def forge_fee_signature(private_key: str, fee: float) -> bytes:
    fee_msg = str(fee).encode()
    private_key_ecdsa = PrivateKey.from_hex(remove_0x_prefix(private_key))
    return private_key_ecdsa.sign_recoverable(fee_msg)


@pytest.fixture
def populate_token_networks_random(
        token_networks: List[TokenNetwork],
        private_keys: List[str],
) -> None:
    random.seed(NUMBER_OF_CHANNELS)
    # seed for pseudo-randomness from config constant, that changes from time to time
    for token_network in token_networks:
        for channel_id in range(NUMBER_OF_CHANNELS):
            private_key1, private_key2 = random.sample(private_keys, 2)
            address1 = Address(private_key_to_address(private_key1))
            address2 = Address(private_key_to_address(private_key2))
            fee1 = abs(random.gauss(0.0002, 0.0001))
            fee2 = abs(random.gauss(0.0002, 0.0001))
            signature1 = forge_fee_signature(private_key1, fee1)
            signature2 = forge_fee_signature(private_key2, fee2)
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
                str(fee1).encode(),
                signature1
            )
            token_network.update_fee(
                channel_id,
                str(fee2).encode(),
                signature2
            )


@pytest.fixture
def populate_token_networks_simple(
    token_networks: List[TokenNetwork],
    private_keys: List[str],
    addresses: List[Address],
    web3: Web3
):
    """ Initializes all token networks with the same default network, consisting of the channels
    described in channel_descriptions.
    The tuples in channel_descriptions define the following:
    (
        p1_index,
        p1_deposit,
        p1_transferred_amount,
        p1_fee,
        p2_index,
        p2_deposit,
        p2_transferred_amount,
        p2_fee
    )
    Topology:
          /-------------\
    0 -- 1 -- 2 -- 3 -- 4    5 -- 6
     \-------/
    """
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
        for token_network in token_networks:
            token_network.handle_channel_opened_event(
                channel_id,
                addresses[p1_index],
                addresses[p2_index]
            )

            token_network.handle_channel_new_deposit_event(
                channel_id,
                addresses[p1_index],
                p1_deposit
            )
            token_network.handle_channel_new_deposit_event(
                channel_id,
                addresses[p2_index],
                p2_deposit
            )

            p1_balance_proof = BalanceProof(
                1,
                p1_transferred_amount,
                EMPTY_MERKLE_ROOT,  # TODO: include some pending locks here
                channel_id,
                token_network.address,
                web3.net.version,
                b'',
                private_key=private_keys[p1_index]
            )
            p2_balance_proof = BalanceProof(
                1,
                p2_transferred_amount,
                EMPTY_MERKLE_ROOT,  # TODO: include some pending locks here
                channel_id,
                token_network.address,
                web3.net.version,
                b'',
                private_key=private_keys[p2_index]
            )
            token_network.update_balance(p1_balance_proof, [])
            token_network.update_balance(p2_balance_proof, [])

            p1_fee_signature = forge_fee_signature(private_keys[p1_index], p1_fee)
            p2_fee_signature = forge_fee_signature(private_keys[p2_index], p2_fee)
            token_network.update_fee(channel_id, str(p1_fee).encode(), p1_fee_signature)
            token_network.update_fee(channel_id, str(p2_fee).encode(), p2_fee_signature)


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
