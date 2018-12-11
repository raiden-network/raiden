from typing import Callable

import pytest

from pathfinder.model.token_network import TokenNetwork
from raiden_contracts.contract_manager import ContractManager, contracts_precompiled_path


@pytest.fixture
def contract_deployer_address(faucet_address) -> str:
    return faucet_address


@pytest.fixture(scope='session')
def contracts_manager():
    return ContractManager(contracts_precompiled_path())


@pytest.fixture
def token_network_model(
    add_and_register_token: Callable,
) -> TokenNetwork:
    token = add_and_register_token(
        initial_amount=1000000,
        decimals=18,
        token_name='PFSTestToken',
        token_symbol='PFS',
    )
    return TokenNetwork(token.address, token.address)
