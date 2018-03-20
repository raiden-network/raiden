import os
from typing import List

import pytest
from raiden_libs.contracts import ContractManager
from web3 import Web3
from web3.contract import get_event_data, Contract

import pathfinder
from pathfinder.contract.token_network_contract import TokenNetworkContract
from pathfinder.utils.types import Address


@pytest.fixture(scope='session')
def contracts_path() -> str:
    module_dir = os.path.dirname(pathfinder.__file__)
    return os.path.join(module_dir, 'contract')


@pytest.fixture(scope='session')
def contract_manager(contracts_path: str):
    return ContractManager(os.path.join(contracts_path, 'contracts_12032018.json'))


@pytest.fixture(scope='session')
def token_addresses(
    web3: Web3,
    contract_manager: ContractManager
) -> List[Address]:

    token = web3.eth.contract(
        abi=contract_manager.get_contract_abi('HumanStandardToken'),
        bytecode=contract_manager.get_contract_bytecode('HumanStandardToken'),
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
def secret_registry_address(
    web3: Web3,
    contract_manager: ContractManager
) -> Address:

    secret_registry = web3.eth.contract(
        abi=contract_manager.get_contract_abi('SecretRegistry'),
        bytecode=contract_manager.get_contract_bytecode('SecretRegistry')
    )

    tx_hash = secret_registry.deploy()
    return web3.eth.getTransactionReceipt(tx_hash).contractAddress


@pytest.fixture(scope='session')
def token_network_addresses(
    web3: Web3,
    contract_manager: ContractManager,
    token_addresses: List[Address],
    secret_registry_address: Address,
) -> List[Address]:

    token_network = web3.eth.contract(
        abi=contract_manager.get_contract_abi('TokenNetwork'),
        bytecode=contract_manager.get_contract_bytecode('TokenNetwork')
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
def token_network_registry(
    web3: Web3,
    contract_manager: ContractManager,
    secret_registry_address: Address,
) -> List[Address]:

    token_network_registry = web3.eth.contract(
        abi=contract_manager.get_contract_abi('TokenNetworkRegistry'),
        bytecode=contract_manager.get_contract_bytecode('TokenNetworkRegistry')
    )
    tx_hash = token_network_registry.deploy(args=(
        secret_registry_address,
    ))

    registry_address = web3.eth.getTransactionReceipt(tx_hash).contractAddress

    token_network_registry = web3.eth.contract(
        registry_address,
        abi=contract_manager.get_contract_abi('TokenNetworkRegistry'),
    )
    return token_network_registry


@pytest.fixture(scope='session')
def token_network_addresses_from_registry(
    web3: Web3,
    contract_manager: ContractManager,
    token_network_registry: Contract,
    token_addresses: List[Address],
) -> List[Address]:

    token_network_addresses = []

    for token_address in token_addresses:
        tx = token_network_registry.functions.createERC20TokenNetwork(token_address).transact()
        receipt = web3.eth.getTransactionReceipt(tx)

        event_data = get_event_data(
            contract_manager.get_event_abi('TokenNetworkRegistry', 'TokenNetworkCreated'),
            receipt['logs'][0]
        )
        token_network_address = event_data['args']['token_network_address']

        token_network_addresses.append(token_network_address)

    return token_network_addresses


@pytest.fixture()
def token_network_contracts(
    web3: Web3,
    contract_manager: ContractManager,
    token_addresses: List[Address],
    token_network_addresses: List[Address],
    contracts_path: str,
    token_network_addresses_from_registry: List[Address],
) -> List[TokenNetworkContract]:

    contracts = [
        TokenNetworkContract(
            web3.eth.contract(
                token_network_address,
                abi=contract_manager.get_contract_abi('TokenNetwork')
            )
        )
        for token_network_address in token_network_addresses
    ]

    return contracts
