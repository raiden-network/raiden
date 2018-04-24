import random
from typing import List, Callable

from unittest.mock import Mock
import pytest
from coincurve import PrivateKey
from eth_utils import remove_0x_prefix
from web3 import Web3
from raiden_contracts.contract_manager import ContractManager
from raiden_libs.blockchain import BlockchainListener
from raiden_libs.utils import EMPTY_MERKLE_ROOT, private_key_to_address
from raiden_libs.test.mocks.blockchain import BlockchainListenerMock

from pathfinder.pathfinding_service import PathfindingService
from pathfinder.model import BalanceProof
from pathfinder.tests.config import NUMBER_OF_CHANNELS
from pathfinder.model.token_network import TokenNetwork
from pathfinder.utils.types import Address


def forge_fee_signature(private_key: str, fee: float) -> bytes:
    fee_msg = str(fee).encode()
    private_key_ecdsa = PrivateKey.from_hex(remove_0x_prefix(private_key))
    return private_key_ecdsa.sign_recoverable(fee_msg)


@pytest.fixture
def channel_descriptions_case_1() -> List:
    """ Creates a network with some edge cases.

    These include disconneced subgraph, depleted channels...
    """

    # Now initialize some channels in this network.
    # The tuples in channel_descriptions define the following:
    # (
    #     p1_index,
    #     p1_deposit,
    #     p1_transferred_amount,
    #     p1_fee,
    #     p2_index,
    #     p2_deposit,
    #     p2_transferred_amount,
    #     p2_fee
    # )
    # Topology:
    #       /-------------\
    # 0 -- 1 -- 2 -- 3 -- 4    5 -- 6
    #  \-------/

    channel_descriptions = [
        (0, 100,  20, 0.0010, 1,  50,  10, 0.0015),  # capacities  90 --  60
        (1,  40,  10, 0.0008, 2, 130, 100, 0.0012),  # capacities 130 --  40
        (2,  90,  10, 0.0007, 3,  10,   0, 0.0010),  # capacities  80 --  10
        (3,  50,  20, 0.0011, 4,  50,  20, 0.0011),  # capacities  50 --  50
        (0,  40,  40, 0.0015, 2,  80,   0, 0.0025),  # capacities   0 -- 120
        (1,  30,  10, 0.0100, 4,  40,  15, 0.0018),  # capacities  35 --  35
        (5, 500, 900, 0.0030, 6, 750, 950, 0.0040),  # capacities 550 -- 700
    ]
    return channel_descriptions


@pytest.fixture
def channel_descriptions_case_2() -> List:
    """ Creates a network with three paths from 0 to 4.

    The paths differ in length and cost.
    """

    # Now initialize some channels in this network.
    # The tuples in channel_descriptions define the following:
    # (
    #     p1_index,
    #     p1_deposit,
    #     p1_transferred_amount,
    #     p1_fee,
    #     p2_index,
    #     p2_deposit,
    #     p2_transferred_amount,
    #     p2_fee
    # )
    # Topology:
    #  /----- 1 ----\
    # 0 -- 2 -- 3 -- 4
    #       \-- 5 --/

    channel_descriptions = [
        (0, 100,  20, 0.3, 1,  50,  10, 0.3),  # capacities  90 --  60
        (1,  40,  10, 0.2, 4, 130, 100, 0.2),  # capacities 130 --  40
        (0,  90,  10, 0.1, 2,  10,   0, 0.1),  # capacities  80 --  10
        (2,  50,  20, 0.2, 3,  50,  20, 0.2),  # capacities  50 --  50
        (3, 100,  40, 0.1, 4,  80,   0, 0.1),  # capacities  60 -- 120
        (2,  30,  10, 0.1, 5,  40,  15, 0.1),  # capacities  35 --  35
        (5, 500, 900, 0.1, 4, 750, 950, 0.1),  # capacities 550 -- 700
    ]
    return channel_descriptions


@pytest.fixture
def blockchain_listener(web3, contracts_manager):
    blockchain_listener = BlockchainListener(
        web3,
        contracts_manager,
        'TokenNetwork',
        poll_interval=0,
    )
    blockchain_listener.required_confirmations = 1
    blockchain_listener.start()
    yield blockchain_listener
    blockchain_listener.stop()


@pytest.fixture
def populate_token_networks_random(
        token_networks: List[TokenNetwork],
        private_keys: List[str],
) -> None:
    # seed for pseudo-randomness from config constant, that changes from time to time
    random.seed(NUMBER_OF_CHANNELS)

    for token_network in token_networks:
        for channel_id in range(NUMBER_OF_CHANNELS):
            private_key1, private_key2 = random.sample(private_keys, 2)
            address1 = Address(private_key_to_address(private_key1))
            address2 = Address(private_key_to_address(private_key2))
            fee1 = abs(random.gauss(0.0002, 0.0001))
            fee2 = abs(random.gauss(0.0002, 0.0001))
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
                address1,
                channel_id + 1,
                fee1
            )

            token_network.update_fee(
                channel_id,
                address2,
                channel_id + 1,
                fee2
            )


@pytest.fixture
def populate_token_networks() -> Callable:
    def populate_token_networks(
        token_networks: List[TokenNetwork],
        private_keys: List[str],
        addresses: List[Address],
        web3: Web3,
        channel_descriptions: List
    ):
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

                token_network.update_fee(
                    channel_identifier=channel_id,
                    signer=addresses[p1_index],
                    nonce=channel_id + 1,
                    new_percentage_fee=p1_fee
                )
                token_network.update_fee(
                    channel_identifier=channel_id,
                    signer=addresses[p2_index],
                    nonce=channel_id + 1,
                    new_percentage_fee=p2_fee
                )

    return populate_token_networks


@pytest.fixture
def populate_token_networks_case_1(
    populate_token_networks: Callable,
    token_networks: List[TokenNetwork],
    private_keys: List[str],
    addresses: List[Address],
    web3: Web3,
    channel_descriptions_case_1: List
):
    populate_token_networks(
        token_networks,
        private_keys,
        addresses,
        web3,
        channel_descriptions_case_1,
    )


@pytest.fixture
def populate_token_networks_case_2(
    populate_token_networks: Callable,
    token_networks: List[TokenNetwork],
    private_keys: List[str],
    addresses: List[Address],
    web3: Web3,
    channel_descriptions_case_2: List
):
    populate_token_networks(
        token_networks,
        private_keys,
        addresses,
        web3,
        channel_descriptions_case_2,
    )


@pytest.fixture
def pathfinding_service_full_mock(
        contracts_manager: ContractManager,
        token_networks: List[TokenNetwork],
) -> PathfindingService:
    pathfinding_service = PathfindingService(
        contracts_manager,
        transport=Mock(),
        token_network_listener=Mock(),
        token_network_registry_listener=Mock()
    )
    pathfinding_service.token_networks = {
        token_network.address: token_network
        for token_network in token_networks
    }

    return pathfinding_service


@pytest.fixture
def pathfinding_service_mocked_listeners(contracts_manager: ContractManager) -> PathfindingService:
    """ Returns a PathfindingService with mocked blockchain listeners. """
    pathfinding_service = PathfindingService(
        contracts_manager,
        transport=Mock(),
        token_network_listener=BlockchainListenerMock(),
        token_network_registry_listener=BlockchainListenerMock()
    )

    return pathfinding_service
