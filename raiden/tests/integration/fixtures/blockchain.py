# -*- coding: utf-8 -*-
from collections import namedtuple

import pytest
import structlog
from eth_utils import decode_hex, to_checksum_address, to_canonical_address

from raiden.utils import (
    get_contract_path,
    privatekey_to_address,
)
from raiden.network.blockchain_service import BlockChainService
from raiden.network.discovery import ContractDiscovery
from raiden.network.rpc.client import JSONRPCClient
from raiden.settings import GAS_PRICE
from raiden.utils.solc import compile_files_cwd

from raiden_contracts.contract_manager import CONTRACT_MANAGER
from raiden_contracts.constants import (
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
)

BlockchainServices = namedtuple(
    'BlockchainServices',
    (
        'deploy_registry',
        'deploy_service',
        'blockchain_services',
    ),
)
log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

# pylint: disable=redefined-outer-name,too-many-arguments,unused-argument,too-many-locals


def _token_addresses(
        token_amount,
        number_of_tokens,
        deploy_service,
        registry,
        participants,
        register,
):
    """ Deploy `number_of_tokens` ERC20 token instances with `token_amount` minted and
    distributed among `blockchain_services`. Optionally the instances will be registered with
    the raiden registry.
    Args:
        token_amount (int): number of units that will be created per token
        number_of_tokens (int): number of token instances that will be created
        deploy_service (BlockchainService): the blockchain connection that will deploy
        participants (list(address)): participant addresses that will receive tokens
        register (bool): switch to control registration with the raiden Registry contract
    """
    result = list()
    for _ in range(number_of_tokens):
        if register:
            token_address = deploy_service.deploy_and_register_token(
                registry,
                contract_name='HumanStandardToken',
                contract_path=get_contract_path('HumanStandardToken.sol'),
                constructor_parameters=(token_amount, 'raiden', 2, 'Rd'),
            )
            result.append(token_address)
        else:
            token_address = deploy_service.deploy_contract(
                contract_name='HumanStandardToken',
                contract_path=get_contract_path('HumanStandardToken.sol'),
                constructor_parameters=(token_amount, 'raiden', 2, 'Rd'),
            )
            result.append(token_address)

        # only the creator of the token starts with a balance (deploy_service),
        # transfer from the creator to the other nodes
        for transfer_to in participants:
            deploy_service.token(token_address).transfer(
                transfer_to,
                token_amount // len(participants),
            )

    return result


@pytest.fixture
def register_tokens():
    """ Should fixture generated tokens be registered with raiden (default: True). """
    return True


@pytest.fixture
def token_addresses(
        request,
        token_amount,
        number_of_tokens,
        blockchain_services,
        register_tokens,
):
    """ Fixture that yields `number_of_tokens` ERC20 token addresses, where the
    `token_amount` (per token) is distributed among the addresses behind `blockchain_services` and
    potentially pre-registered with the raiden Registry.
    The following arguments can control the behavior:

    Args:
        token_amount (int): the overall number of units minted per token
        number_of_tokens (int): the number of token instances
        register_tokens (bool): controls if tokens will be registered with raiden Registry
    """

    participants = [
        privatekey_to_address(blockchain_service.private_key) for
        blockchain_service in blockchain_services.blockchain_services
    ]
    token_addresses = _token_addresses(
        token_amount,
        number_of_tokens,
        blockchain_services.deploy_service,
        blockchain_services.deploy_registry,
        participants,
        register_tokens,
    )

    return token_addresses


@pytest.fixture
def endpoint_discovery_services(blockchain_services):
    discovery_address = blockchain_services.deploy_service.deploy_contract(
        'EndpointRegistry',
        get_contract_path('EndpointRegistry.sol'),
    )

    return [
        ContractDiscovery(chain.node_address, chain.discovery(discovery_address))
        for chain in blockchain_services.blockchain_services
    ]


@pytest.fixture
def chain_id(blockchain_services, deploy_client):
    return int(deploy_client.web3.version.network)


def deploy_contract_web3(
        contract_name: str,
        poll_timeout,
        deploy_client,
        *args,
):
    web3 = deploy_client.web3

    contract_interface = CONTRACT_MANAGER.abi[contract_name]
    contract = web3.eth.contract(
        abi=contract_interface['abi'],
        bytecode=contract_interface['bin'],
    )
    # Submit the transaction that deploys the contract
    tx_hash = contract.constructor(*args).transact(
        {'from': to_checksum_address(deploy_client.sender)},
    )

    deploy_client.poll(tx_hash, timeout=poll_timeout)
    receipt = web3.eth.getTransactionReceipt(tx_hash)

    contract_address = receipt['contractAddress']
    return to_canonical_address(contract_address)


@pytest.fixture
def deploy_client(init_blockchain, blockchain_rpc_ports, deploy_key, web3):
    host = '0.0.0.0'
    rpc_port = blockchain_rpc_ports[0]

    return JSONRPCClient(
        host,
        rpc_port,
        deploy_key,
        web3=web3,
    )


def _jsonrpc_services(
        deploy_key,
        deploy_client,
        private_keys,
        verbose,
        poll_timeout,
        deploy_new_contracts,
        registry_address=None,
        web3=None,
):
    deploy_blockchain = BlockChainService(
        deploy_key,
        deploy_client,
        GAS_PRICE,
    )

    if deploy_new_contracts:
        # secret registry
        secret_registry_address = deploy_contract_web3(
            CONTRACT_SECRET_REGISTRY,
            poll_timeout,
            deploy_client,
        )
        secret_registry = deploy_blockchain.secret_registry(secret_registry_address)  # noqa

        network_registry_address = deploy_contract_web3(
            CONTRACT_TOKEN_NETWORK_REGISTRY,
            poll_timeout,
            deploy_client,
            to_checksum_address(secret_registry_address),
            deploy_blockchain.network_id,
        )
        network_registry = deploy_blockchain.token_network_registry(network_registry_address)  # noqa

    # we cannot instantiate BlockChainService without a registry, so first
    # deploy it directly with a JSONRPCClient
    if registry_address is None:
        registry_path = get_contract_path('Registry.sol')
        registry_contracts = compile_files_cwd([registry_path])

        log.info('Deploying registry contract')
        registry_proxy = deploy_client.deploy_solidity_contract(
            'Registry',
            registry_contracts,
            dict(),
            tuple(),
            contract_path=registry_path,
            timeout=poll_timeout,
        )
        registry_address = decode_hex(registry_proxy.contract.address)

    # at this point the blockchain must be running, this will overwrite the
    # method so even if the client is patched twice, it should work fine

    deploy_registry = deploy_blockchain.registry(registry_address)

    host = '0.0.0.0'
    blockchain_services = list()
    for privkey in private_keys:
        rpc_client = JSONRPCClient(
            host,
            deploy_client.port,
            privkey,
            web3=web3,
        )

        blockchain = BlockChainService(
            privkey,
            rpc_client,
            GAS_PRICE,
        )
        blockchain_services.append(blockchain)

    return BlockchainServices(
        deploy_registry,
        deploy_blockchain,
        blockchain_services,
    )


@pytest.fixture
def blockchain_services(
        request,
        deploy_key,
        deploy_client,
        private_keys,
        poll_timeout,
        web3,
):
    return _jsonrpc_services(
        deploy_key,
        deploy_client,
        private_keys,
        request.config.option.verbose,
        poll_timeout,
        None,  # _jsonrpc_services will handle the None value
        web3=web3,
    )
