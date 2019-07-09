import os
from typing import Any, List, Tuple

from solc import compile_files

from raiden.network.blockchain_service import BlockChainService
from raiden.network.pathfinding import get_random_pfs
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.utils import typing
from raiden.utils.smart_contracts import deploy_contract_web3
from raiden_contracts.contract_manager import ContractManager


def deploy_token(
    deploy_client: JSONRPCClient,
    contract_manager: ContractManager,
    initial_amount: typing.TokenAmount,
    decimals: int,
    token_name: str,
    token_symbol: str,
    token_contract_name: str,
) -> ContractProxy:
    token_address = deploy_contract_web3(
        contract_name=token_contract_name,
        deploy_client=deploy_client,
        contract_manager=contract_manager,
        constructor_arguments=(initial_amount, decimals, token_name, token_symbol),
    )

    contract_abi = contract_manager.get_contract_abi(token_contract_name)
    return deploy_client.new_contract_proxy(
        contract_interface=contract_abi, contract_address=token_address
    )


def deploy_tokens_and_fund_accounts(
    token_amount: int,
    number_of_tokens: int,
    deploy_service: BlockChainService,
    participants: typing.List[typing.Address],
    contract_manager: ContractManager,
    token_contract_name: str,
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
            token_contract_name,
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
    pfs_address = get_random_pfs(c1_service_proxy, "latest")
    assert pfs_address is None

    # Test that setting the urls works
    c1_service_proxy.set_url(urls[0])
    c2_service_proxy.set_url(urls[1])
    c3_service_proxy.set_url(urls[2])

    return c1_service_proxy, urls


def compile_files_cwd(*args: Any, **kwargs: Any) -> str:
    """change working directory to contract's dir in order to avoid symbol
    name conflicts"""
    # get root directory of the contracts
    compile_wd = os.path.commonprefix(args[0])
    # edge case - compiling a single file
    if os.path.isfile(compile_wd):
        compile_wd = os.path.dirname(compile_wd)
    # remove prefix from the files
    if compile_wd[-1] != "/":
        compile_wd += "/"
    file_list = [x.replace(compile_wd, "") for x in args[0]]
    cwd = os.getcwd()
    try:
        os.chdir(compile_wd)
        compiled_contracts = compile_files(
            source_files=file_list,
            # We need to specify output values here because py-solc by default
            # provides them all and does not know that "clone-bin" does not exist
            # in solidity >= v0.5.0
            output_values=("abi", "asm", "ast", "bin", "bin-runtime"),
            **kwargs,
        )
    finally:
        os.chdir(cwd)
    return compiled_contracts


def deploy_rpc_test_contract(deploy_client, name: str):
    contract_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "smart_contracts", f"{name}.sol")
    )
    contracts = compile_files_cwd([contract_path])
    contract_key = os.path.basename(contract_path) + ":" + name

    contract_proxy, receipt = deploy_client.deploy_single_contract(
        contract_name=name, contract=contracts[contract_key]
    )

    return contract_proxy, receipt


def get_list_of_block_numbers(item):
    """ Creates a list of block numbers of the given list/single event"""
    if isinstance(item, list):
        return [element["blockNumber"] for element in item]

    if isinstance(item, dict):
        block_number = item["blockNumber"]
        return [block_number]

    return list()
