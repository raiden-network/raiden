from typing import List, Callable

import pytest
from raiden_contracts.contract_manager import ContractManager, CONTRACTS_SOURCE_DIRS
from raiden_libs.types import Address

from pathfinder.model.token_network import TokenNetwork


@pytest.fixture
def contract_deployer_address(faucet_address) -> str:
    return faucet_address


@pytest.fixture(scope='session')
def contracts_manager():
    return ContractManager(CONTRACTS_SOURCE_DIRS)


@pytest.fixture
def token_networks(
    add_and_register_token: Callable,
) -> List[TokenNetwork]:
    return [
        TokenNetwork(add_and_register_token(
            initial_amount=1000000,
            decimals=18,
            token_name=f'TestToken{i}',
            token_symbol=f'TT{i}'
        ).address)
        for i in range(4)
    ]


@pytest.fixture
def token_network_addresses(
    token_networks: List[TokenNetwork],
) -> List[Address]:
    return [token_network.address for token_network in token_networks]
