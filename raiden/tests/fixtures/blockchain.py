import pytest

from raiden.constants import Environment
from raiden.settings import DEVELOPMENT_CONTRACT_VERSION, PRODUCTION_CONTRACT_VERSION
from raiden_contracts.contract_manager import ContractManager, contracts_precompiled_path


@pytest.fixture
def contracts_path(environment_type):
    version = PRODUCTION_CONTRACT_VERSION
    if environment_type == Environment.DEVELOPMENT:
        version = DEVELOPMENT_CONTRACT_VERSION

    return contracts_precompiled_path(version)


@pytest.fixture
def contract_manager(contracts_path):
    return ContractManager(contracts_path)
