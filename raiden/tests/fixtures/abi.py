# -*- coding: utf-8 -*-
import pytest

from raiden.blockchain.abi import CONTRACT_MANAGER


@pytest.fixture(scope='session')
def token_abi():
    return CONTRACT_MANAGER.get_abi('human_standard_token')


@pytest.fixture(scope='session')
def registry_abi():
    return CONTRACT_MANAGER.get_abi('registry')


@pytest.fixture(scope='session')
def channel_manager_abi():
    return CONTRACT_MANAGER.get_abi('channel_manager')


@pytest.fixture(scope='session')
def netting_channel_abi():
    return CONTRACT_MANAGER.get_abi('netting_channel')
