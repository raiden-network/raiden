from functools import partial
from typing import List

import pytest
from _pytest.monkeypatch import MonkeyPatch
from eth_utils import encode_hex, keccak, to_checksum_address
from web3 import Web3
from raiden_libs.contracts import ContractManager

from pathfinder.contract.token_network_contract import TokenNetworkContract
from pathfinder.utils.types import Address


@pytest.fixture(scope='session')
def token_addresses() -> List[Address]:
    # TODO: actually deploy some token contracts here
    offset = 369874125
    return [to_checksum_address(encode_hex(keccak(offset + i)[:20])) for i in range(4)]


@pytest.fixture(scope='session')
def token_network_addresses() -> List[Address]:
    # TODO: actually deploy some token network contracts here
    offset = 987412365
    return [to_checksum_address(encode_hex(keccak(offset + i)[:20])) for i in range(4)]


@pytest.fixture()
def token_network_contracts(
    web3: Web3,
    token_addresses: List[Address],
    token_network_addresses: List[Address],
    monkeypatch: MonkeyPatch
) -> List[TokenNetworkContract]:
    cm = ContractManager('pathfinder/contract/contracts_12032018.json')
    contracts = [
        TokenNetworkContract(
            web3.eth.contract(
                token_network_address,
                abi=cm.get_contract_abi('TokenNetwork')
            )
        )
        for token_network_address in token_network_addresses
    ]

    # TODO: remove monkeypatching to replace with calls to the actual, deployed contract
    def get_token_address_patched(i: int):
        return token_addresses[i]
    for i, contract in enumerate(contracts):
        monkeypatch.setattr(contract, 'get_token_address', partial(get_token_address_patched, i))

    return contracts
