import random
from typing import Callable, Generator, List
from unittest.mock import Mock, patch

import pytest
from web3 import Web3

from pathfinder.model.token_network import TokenNetwork
from pathfinder.pathfinding_service import PathfindingService
from pathfinder.tests.config import NUMBER_OF_CHANNELS
from pathfinder.tests.mocks.blockchain_listener import BlockchainListenerMock
from raiden_contracts.contract_manager import ContractManager
from raiden_libs.types import Address, ChannelIdentifier
from raiden_libs.utils import private_key_to_address


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
        (0, 100,  20,  10, 1,  50,  10, 15),  # capacities  90 --  60
        (1,  40,  10,   8, 2, 130, 100, 12),  # capacities 130 --  40
        (2,  90,  10,   7, 3,  10,   0, 10),  # capacities  80 --  10
        (3,  50,  20,  11, 4,  50,  20, 11),  # capacities  50 --  50
        (0,  40,  40,  15, 2,  80,   0, 25),  # capacities   0 -- 120
        (1,  30,  10, 100, 4,  40,  15, 18),  # capacities  35 --  35
        (5, 500, 900,  30, 6, 750, 950, 40),  # capacities 550 -- 700
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
        (0, 100,  20, 3000, 1,  50,  10, 3000),  # capacities  90 --  60
        (1,  40,  10, 2000, 4, 130, 100, 2000),  # capacities 130 --  40
        (0,  90,  10, 1000, 2,  10,   0, 1000),  # capacities  80 --  10
        (2,  50,  20, 1500, 3,  50,  20, 1500),  # capacities  50 --  50
        (3, 100,  40, 1000, 4,  80,   0, 1000),  # capacities  60 -- 120
        (2,  30,  10, 1000, 5,  40,  15, 1000),  # capacities  35 --  35
        (5, 500, 900, 1000, 4, 750, 950, 1000),  # capacities 550 -- 700
    ]
    return channel_descriptions


@pytest.fixture
def populate_token_network_random(
        token_network_model: TokenNetwork,
        private_keys: List[str],
) -> None:
    # seed for pseudo-randomness from config constant, that changes from time to time
    random.seed(NUMBER_OF_CHANNELS)

    for channel_id_int in range(NUMBER_OF_CHANNELS):
        channel_id = ChannelIdentifier(channel_id_int)

        private_key1, private_key2 = random.sample(private_keys, 2)
        address1 = Address(private_key_to_address(private_key1))
        address2 = Address(private_key_to_address(private_key2))
        token_network_model.handle_channel_opened_event(
            channel_id,
            address1,
            address2,
        )

        # deposit to channels
        deposit1, deposit2 = random.sample(range(1000), 2)
        address1, address2 = token_network_model.channel_id_to_addresses[channel_id]
        token_network_model.handle_channel_new_deposit_event(
            channel_id,
            address1,
            deposit1,
        )
        token_network_model.handle_channel_new_deposit_event(
            channel_id,
            address2,
            deposit2,
        )


@pytest.fixture
def populate_token_network() -> Callable:
    def populate_token_network(
        token_network: TokenNetwork,
        private_keys: List[str],
        addresses: List[Address],
        web3: Web3,
        channel_descriptions: List,
    ):
        for channel_id, (
            p1_index,
            p1_deposit,
            _p1_transferred_amount,
            _p1_fee,
            p2_index,
            p2_deposit,
            _p2_transferred_amount,
            _p2_fee,
        ) in enumerate(channel_descriptions):
            token_network.handle_channel_opened_event(
                ChannelIdentifier(channel_id),
                addresses[p1_index],
                addresses[p2_index],
            )

            token_network.handle_channel_new_deposit_event(
                ChannelIdentifier(channel_id),
                addresses[p1_index],
                p1_deposit,
            )
            token_network.handle_channel_new_deposit_event(
                ChannelIdentifier(channel_id),
                addresses[p2_index],
                p2_deposit,
            )

    return populate_token_network


@pytest.fixture
def populate_token_network_case_1(
    populate_token_network: Callable,
    token_network_model: TokenNetwork,
    private_keys: List[str],
    addresses: List[Address],
    web3: Web3,
    channel_descriptions_case_1: List,
):
    populate_token_network(
        token_network_model,
        private_keys,
        addresses,
        web3,
        channel_descriptions_case_1,
    )


@pytest.fixture
def populate_token_network_case_2(
    populate_token_network: Callable,
    token_network_model: TokenNetwork,
    private_keys: List[str],
    addresses: List[Address],
    web3: Web3,
    channel_descriptions_case_2: List,
):
    populate_token_network(
        token_network_model,
        private_keys,
        addresses,
        web3,
        channel_descriptions_case_2,
    )


@pytest.fixture
def pathfinding_service_full_mock(
    contracts_manager: ContractManager,
    token_network_model: TokenNetwork,
) -> Generator[PathfindingService, None, None]:
    with patch('pathfinder.pathfinding_service.BlockchainListener', new=Mock):
        web3_mock = Mock()
        web3_mock.net.version = '1'

        pathfinding_service = PathfindingService(
            web3=web3_mock,
            contract_manager=contracts_manager,
            registry_address='',
        )
        pathfinding_service.token_networks = {
            token_network_model.address: token_network_model,
        }

        yield pathfinding_service


@pytest.fixture
def pathfinding_service_mocked_listeners(
    contracts_manager: ContractManager,
    web3: Web3,
) -> Generator[PathfindingService, None, None]:
    """ Returns a PathfindingService with mocked blockchain listeners. """
    with patch('pathfinder.pathfinding_service.BlockchainListener', new=BlockchainListenerMock):
        pathfinding_service = PathfindingService(
            web3=web3,
            contract_manager=contracts_manager,
            registry_address='',
        )

        yield pathfinding_service
