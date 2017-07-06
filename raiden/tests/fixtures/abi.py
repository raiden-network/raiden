# -*- coding: utf-8 -*-
import pytest

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_CHANNEL_MANAGER,
    CONTRACT_HUMAN_STANDARD_TOKEN,
    CONTRACT_NETTING_CHANNEL,
    CONTRACT_REGISTRY,
)


@pytest.fixture(scope='session')
def token_abi():
    return CONTRACT_MANAGER.get_abi(CONTRACT_HUMAN_STANDARD_TOKEN)


@pytest.fixture(scope='session')
def registry_abi():
    return CONTRACT_MANAGER.get_abi(CONTRACT_REGISTRY)


@pytest.fixture(scope='session')
def channel_manager_abi():
    return CONTRACT_MANAGER.get_abi(CONTRACT_CHANNEL_MANAGER)


@pytest.fixture(scope='session')
def netting_channel_abi():
    return CONTRACT_MANAGER.get_abi(CONTRACT_NETTING_CHANNEL)
