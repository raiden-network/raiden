import pytest

from raiden.settings import RAIDEN_CONTRACT_VERSION
from raiden_contracts.contract_manager import ContractManager, contracts_precompiled_path


@pytest.fixture
def contracts_path():
    version = RAIDEN_CONTRACT_VERSION
    return contracts_precompiled_path(version)


@pytest.fixture
def contract_manager(contracts_path):
    return ContractManager(contracts_path)
