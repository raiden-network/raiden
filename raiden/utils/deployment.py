import structlog
from eth_utils import to_checksum_address

from raiden.utils import get_contract_path
from raiden.utils.solc import compile_files_cwd

log = structlog.get_logger(__name__)


# Source files for all to be deployed solidity contracts
RAIDEN_CONTRACT_FILES = [
    'NettingChannelLibrary.sol',
    'ChannelManagerLibrary.sol',
    'Registry.sol',
]

# Top level contracts to be deployed. Dependencies are handled automatically
# in `JSONRPCClient.deploy_solidity_contract()`
CONTRACTS_TO_DEPLOY = [
    'Registry.sol:Registry',
]

NEW_CONTRACTS_TO_DEPLOY = [
    'EndpointRegistry',
    'SecretRegistry',
]


def deploy_file(contract, compiled_contracts, client):
    libraries = dict()
    filename, _, name = contract.partition(":")
    log.info(f"Deploying {name}")
    proxy = client.deploy_solidity_contract(
        name,
        compiled_contracts,
        libraries,
        '',
        contract_path=filename,
    )

    log.info(f"Deployed {name} @ {to_checksum_address(proxy.contract_address)}")
    libraries[name] = proxy.contract_address
    return libraries


def deploy_contracts(client, compile_list=None, deploy_list=None):
    if compile_list is None:
        compile_list = RAIDEN_CONTRACT_FILES
    if deploy_list is None:
        deploy_list = CONTRACTS_TO_DEPLOY

    contracts_expanded = [
        get_contract_path(x)
        for x in compile_list
    ]
    compiled_contracts = compile_files_cwd(contracts_expanded)
    deployed = {}
    for contract in deploy_list:
        deployed.update(deploy_file(contract, compiled_contracts, client))
    return deployed
