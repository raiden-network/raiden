from eth_utils import to_normalized_address
from web3.exceptions import BadFunctionCallOutput

from raiden.exceptions import AddressWrongContract, ContractVersionMismatch
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.utils.typing import Address


def compare_contract_versions(
        proxy: ContractProxy,
        expected_version: str,
        contract_name: str,
        address: Address,
) -> None:
    """Compare version strings of a contract.

    If not matching raise ContractVersionMismatch. Also may raise AddressWrongContract
    if the contract contains no code."""
    assert isinstance(expected_version, str)
    try:
        deployed_version = proxy.contract.functions.contract_version().call()
    except BadFunctionCallOutput:
        raise AddressWrongContract('')

    deployed_version = deployed_version.replace('_', '0')
    expected_version = expected_version.replace('_', '0')

    deployed = [int(x) for x in deployed_version.split('.')]
    expected = [int(x) for x in expected_version.split('.')]

    if deployed != expected:
        raise ContractVersionMismatch(
            f'Provided {contract_name} contract ({to_normalized_address(address)}) '
            f'version mismatch. Expected: {expected_version} Got: {deployed_version}',
        )
