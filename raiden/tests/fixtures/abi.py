# -*- coding: utf-8 -*-
import pytest

from raiden.blockchain.abi import (
    HUMAN_TOKEN_ABI,
    CHANNEL_MANAGER_ABI,
    NETTING_CHANNEL_ABI,
    REGISTRY_ABI,
)


@pytest.fixture(scope='session')
def token_abi():
    return HUMAN_TOKEN_ABI


@pytest.fixture(scope='session')
def registry_abi():
    return REGISTRY_ABI


@pytest.fixture(scope='session')
def channel_manager_abi():
    return CHANNEL_MANAGER_ABI


@pytest.fixture(scope='session')
def netting_channel_abi():
    return NETTING_CHANNEL_ABI
