from typing import List

import pytest
from eth_utils import encode_hex, is_hex, keccak, remove_0x_prefix

from pathfinder.utils import private_key_to_address
from pathfinder.utils.types import Address


@pytest.fixture(scope='session')
def faucet_private_key(request) -> str:
    private_key = request.config.getoption('faucet_private_key')
    if is_hex(private_key):
        assert len(remove_0x_prefix(private_key)) == 64
        return private_key
    # TODO: support private keys from file


@pytest.fixture(scope='session')
def faucet_address(faucet_private_key: str):
    return private_key_to_address(faucet_private_key)


@pytest.fixture(scope='session')
def private_keys() -> List[str]:
    offset = 14789632
    return [encode_hex(keccak(offset + i)) for i in range(2)]


@pytest.fixture(scope='session')
def addresses(private_keys: List[str]) -> List[Address]:
    return [private_key_to_address(private_key) for private_key in private_keys]


@pytest.fixture(scope='session')
def initiator_private_key(private_keys: List[str]) -> str:
    return private_keys[0]


@pytest.fixture(scope='session')
def target_private_key(private_keys: List[str]) -> str:
    return private_keys[1]


@pytest.fixture(scope='session')
def initiator_address(initiator_private_key: str) -> Address:
    return private_key_to_address(initiator_private_key)


@pytest.fixture(scope='session')
def target_address(target_private_key: str) -> Address:
    return private_key_to_address(target_private_key)
