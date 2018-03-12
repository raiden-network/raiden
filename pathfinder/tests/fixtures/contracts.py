from typing import List

import pytest
from web3 import Web3
from raiden_libs.contracts import ContractManager

from pathfinder.contract.token_network_contract import TokenNetworkContract
from pathfinder.utils.types import Address


@pytest.fixture(scope='session')
def contract_manager():
    return ContractManager('pathfinder/contract/contracts_12032018.json')


@pytest.fixture(scope='session')
def token_addresses(web3, contract_manager) -> List[Address]:
    token = web3.eth.contract(
        abi=contract_manager.data['HumanStandardToken']['abi'],
        bytecode=contract_manager.data['HumanStandardToken']['bytecode']
    )

    addresses = list()
    for i in range(4):
        tx_hash = token.deploy(args=(
            1_000_000,  # initial amount
            18,  # decimal units
            f'TestToken{i}',  # Token name
            f'TT{i}',  # Token symbol
        ))

        addresses.append(web3.eth.getTransactionReceipt(tx_hash).contractAddress)

    return addresses


@pytest.fixture(scope='session')
def secret_registry_address(web3, contract_manager) -> Address:
    secret_registry = web3.eth.contract(
        abi=contract_manager.data['SecretRegistry']['abi'],
        bytecode=contract_manager.data['SecretRegistry']['bytecode']
    )

    tx_hash = secret_registry.deploy()
    return web3.eth.getTransactionReceipt(tx_hash).contractAddress


@pytest.fixture(scope='session')
def token_network_addresses(
    web3,
    contract_manager,
    token_addresses,
    secret_registry_address
) -> List[Address]:

    token_network = web3.eth.contract(
        abi=contract_manager.data['TokenNetwork']['abi'],
        bytecode=contract_manager.data['TokenNetwork']['bytecode']
    )

    addresses = list()
    for token_address in token_addresses:
        tx_hash = token_network.deploy(args=(
            token_address,
            secret_registry_address,
        ))

        addresses.append(web3.eth.getTransactionReceipt(tx_hash).contractAddress)

    return addresses


@pytest.fixture(scope='session')
def token_network_registry_address(
    web3,
    contract_manager,
    secret_registry_address
) -> List[Address]:

    token_network_registry = web3.eth.contract(
        abi=contract_manager.data['TokenNetworkRegistry']['abi'],
        bytecode=contract_manager.data['TokenNetworkRegistry']['bytecode']
    )

    tx_hash = token_network_registry.deploy(args=(
        secret_registry_address,
    ))

    return web3.eth.getTransactionReceipt(tx_hash).contractAddress


@pytest.fixture()
def token_network_contracts(
    web3: Web3,
    token_addresses: List[Address],
    token_network_addresses: List[Address],
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

    return contracts
