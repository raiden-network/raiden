from eth_utils import to_canonical_address

from raiden.network.rpc.client import JSONRPCClient
from raiden.utils.typing import Address, Any, Tuple
from raiden_contracts.contract_manager import ContractManager


def deploy_contract_web3(
        contract_name: str,
        deploy_client: JSONRPCClient,
        contract_manager: ContractManager,
        constructor_arguments: Tuple[Any, ...] = (),
) -> Address:
    compiled = {
        contract_name: contract_manager.get_contract(contract_name),
    }
    contract_proxy, _ = deploy_client.deploy_solidity_contract(
        contract_name=contract_name,
        all_contracts=compiled,
        constructor_parameters=constructor_arguments,
    )
    return Address(to_canonical_address(contract_proxy.contract.address))
