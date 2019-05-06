import os
from typing import List, Tuple

from raiden.network.blockchain_service import BlockChainService
from raiden.network.pathfinding import get_random_service
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.utils import typing
from raiden.utils.smart_contracts import deploy_contract_web3
from raiden.utils.solc import compile_files_cwd
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN
from raiden_contracts.contract_manager import ContractManager


def deploy_token(
    deploy_client: JSONRPCClient,
    contract_manager: ContractManager,
    initial_amount: typing.TokenAmount,
    decimals: int,
    token_name: str,
    token_symbol: str,
) -> ContractProxy:
    token_address = deploy_contract_web3(
        contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
        deploy_client=deploy_client,
        contract_manager=contract_manager,
        constructor_arguments=(initial_amount, decimals, token_name, token_symbol),
    )

    contract_abi = contract_manager.get_contract_abi(CONTRACT_HUMAN_STANDARD_TOKEN)
    return deploy_client.new_contract_proxy(
        contract_interface=contract_abi, contract_address=token_address
    )


def deploy_tokens_and_fund_accounts(
    token_amount: int,
    number_of_tokens: int,
    deploy_service: BlockChainService,
    participants: typing.List[typing.Address],
    contract_manager: ContractManager,
) -> typing.List[typing.TokenAddress]:
    """ Deploy `number_of_tokens` ERC20 token instances with `token_amount` minted and
    distributed among `blockchain_services`. Optionally the instances will be registered with
    the raiden registry.

    Args:
        token_amount (int): number of units that will be created per token
        number_of_tokens (int): number of token instances that will be created
        deploy_service (BlockChainService): the blockchain connection that will deploy
        participants (list(address)): participant addresses that will receive tokens
    """
    result = list()
    for _ in range(number_of_tokens):
        token_address = deploy_contract_web3(
            CONTRACT_HUMAN_STANDARD_TOKEN,
            deploy_service.client,
            contract_manager=contract_manager,
            constructor_arguments=(token_amount, 2, "raiden", "Rd"),
        )

        result.append(token_address)

        # only the creator of the token starts with a balance (deploy_service),
        # transfer from the creator to the other nodes
        for transfer_to in participants:
            deploy_service.token(token_address).transfer(
                to_address=transfer_to, amount=token_amount // len(participants)
            )

    return result


def deploy_service_registry_and_set_urls(
    private_keys, web3, contract_manager, service_registry_address
) -> Tuple[ServiceRegistry, List[str]]:
    urls = ["http://foo", "http://boo", "http://coo"]
    c1_client = JSONRPCClient(web3, private_keys[0])
    c1_service_proxy = ServiceRegistry(
        jsonrpc_client=c1_client,
        service_registry_address=service_registry_address,
        contract_manager=contract_manager,
    )
    c2_client = JSONRPCClient(web3, private_keys[1])
    c2_service_proxy = ServiceRegistry(
        jsonrpc_client=c2_client,
        service_registry_address=service_registry_address,
        contract_manager=contract_manager,
    )
    c3_client = JSONRPCClient(web3, private_keys[2])
    c3_service_proxy = ServiceRegistry(
        jsonrpc_client=c3_client,
        service_registry_address=service_registry_address,
        contract_manager=contract_manager,
    )

    # Test that getting a random service for an empty registry returns None
    pfs_address, pfs_eth_address = get_random_service(c1_service_proxy, "latest")
    assert pfs_address is None
    assert pfs_eth_address is None

    # Test that setting the urls works
    c1_service_proxy.set_url(urls[0])
    c2_service_proxy.set_url(urls[1])
    c3_service_proxy.set_url(urls[2])

    return c1_service_proxy, urls


def get_test_contract(name):
    contract_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "smart_contracts", name)
    )
    contracts = compile_files_cwd([contract_path])

    return contract_path, contracts


def deploy_rpc_test_contract(deploy_client, name):
    contract_path, contracts = get_test_contract(f"{name}.sol")
    contract_proxy, _ = deploy_client.deploy_solidity_contract(
        name, contracts, libraries=dict(), constructor_parameters=None, contract_path=contract_path
    )

    return contract_proxy


def get_list_of_block_numbers(item):
    """ Creates a list of block numbers of the given list/single event"""
    if isinstance(item, list):
        return [element["blockNumber"] for element in item]

    if isinstance(item, dict):
        block_number = item["blockNumber"]
        return [block_number]

    return list()
