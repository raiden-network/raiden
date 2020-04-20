import os

from solc import compile_files
from web3.contract import Contract
from web3.types import TxReceipt

from raiden.constants import BLOCK_ID_LATEST
from raiden.network.pathfinding import get_random_pfs
from raiden.network.proxies.custom_token import CustomToken
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.utils.typing import Any, Dict, List, TokenAmount, Tuple
from raiden_contracts.contract_manager import ContractManager


def deploy_token(
    deploy_client: JSONRPCClient,
    contract_manager: ContractManager,
    initial_amount: TokenAmount,
    decimals: int,
    token_name: str,
    token_symbol: str,
    token_contract_name: str,
) -> Contract:
    contract_proxy, _ = deploy_client.deploy_single_contract(
        contract_name=token_contract_name,
        contract=contract_manager.get_contract(token_contract_name),
        constructor_parameters=(initial_amount, decimals, token_name, token_symbol),
    )
    return contract_proxy


def deploy_service_registry_and_set_urls(
    private_keys, web3, contract_manager, service_registry_address
) -> Tuple[ServiceRegistry, List[str]]:
    urls = ["http://foo", "http://boo", "http://coo"]
    block_identifier = BLOCK_ID_LATEST
    c1_client = JSONRPCClient(web3, private_keys[0])
    c1_service_proxy = ServiceRegistry(
        jsonrpc_client=c1_client,
        service_registry_address=service_registry_address,
        contract_manager=contract_manager,
        block_identifier=block_identifier,
    )
    token_address = c1_service_proxy.token_address(block_identifier=block_identifier)
    c1_token_proxy = CustomToken(
        jsonrpc_client=c1_client,
        token_address=token_address,
        contract_manager=contract_manager,
        block_identifier=block_identifier,
    )
    c2_client = JSONRPCClient(web3, private_keys[1])
    c2_service_proxy = ServiceRegistry(
        jsonrpc_client=c2_client,
        service_registry_address=service_registry_address,
        contract_manager=contract_manager,
        block_identifier=block_identifier,
    )
    c2_token_proxy = CustomToken(
        jsonrpc_client=c2_client,
        token_address=token_address,
        contract_manager=contract_manager,
        block_identifier=block_identifier,
    )
    c3_client = JSONRPCClient(web3, private_keys[2])
    c3_service_proxy = ServiceRegistry(
        jsonrpc_client=c3_client,
        service_registry_address=service_registry_address,
        contract_manager=contract_manager,
        block_identifier=block_identifier,
    )
    c3_token_proxy = CustomToken(
        jsonrpc_client=c3_client,
        token_address=token_address,
        contract_manager=contract_manager,
        block_identifier=block_identifier,
    )

    # Test that getting a random service for an empty registry returns None
    pfs_address = get_random_pfs(
        c1_service_proxy, BLOCK_ID_LATEST, pathfinding_max_fee=TokenAmount(1)
    )
    assert pfs_address is None

    log_details: Dict[str, Any] = {}
    # Test that setting the urls works
    c1_price = c1_service_proxy.current_price(block_identifier=BLOCK_ID_LATEST)
    c1_token_proxy.mint_for(c1_price, c1_client.address)
    assert c1_token_proxy.balance_of(c1_client.address) > 0
    c1_token_proxy.approve(allowed_address=service_registry_address, allowance=c1_price)
    c1_service_proxy.deposit(block_identifier=BLOCK_ID_LATEST, limit_amount=c1_price)
    c1_service_proxy.set_url(urls[0])

    c2_price = c2_service_proxy.current_price(block_identifier=BLOCK_ID_LATEST)
    c2_token_proxy.mint_for(c2_price, c2_client.address)
    assert c2_token_proxy.balance_of(c2_client.address) > 0
    c2_token_proxy.approve(allowed_address=service_registry_address, allowance=c2_price)
    c2_service_proxy.deposit(block_identifier=BLOCK_ID_LATEST, limit_amount=c2_price)
    c2_service_proxy.set_url(urls[1])

    c3_price = c3_service_proxy.current_price(block_identifier=BLOCK_ID_LATEST)
    c3_token_proxy.mint_for(c3_price, c3_client.address)
    assert c3_token_proxy.balance_of(c3_client.address) > 0
    c3_token_proxy.approve(allowed_address=service_registry_address, allowance=c3_price)
    c3_service_proxy.deposit(block_identifier=BLOCK_ID_LATEST, limit_amount=c3_price)
    c3_token_proxy.client.estimate_gas(c3_token_proxy.proxy, "mint", log_details, c3_price)
    c3_token_proxy.approve(allowed_address=service_registry_address, allowance=c3_price)
    c3_service_proxy.set_url(urls[2])

    return c1_service_proxy, urls


def compile_files_cwd(*args: Any, **kwargs: Any) -> Dict[str, Any]:
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


def deploy_rpc_test_contract(
    deploy_client: JSONRPCClient, name: str
) -> Tuple[Contract, TxReceipt]:
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
