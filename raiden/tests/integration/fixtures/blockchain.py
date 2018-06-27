import pytest
import structlog

from raiden.network.discovery import ContractDiscovery
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.network import jsonrpc_services
from raiden.tests.utils.smartcontracts import (
    deploy_tokens_and_fund_accounts,
)
from raiden.utils import (
    get_contract_path,
    privatekey_to_address,
)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

# pylint: disable=redefined-outer-name,too-many-arguments,unused-argument,too-many-locals


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
        privatekey_to_address(blockchain_service.private_key)
        for blockchain_service in blockchain_services.blockchain_services
    ]
    token_addresses = deploy_tokens_and_fund_accounts(
        token_amount,
        number_of_tokens,
        blockchain_services.deploy_service,
        participants,
    )

    if register_tokens:
        for token in token_addresses:
            blockchain_services.deploy_registry.add_token(token)

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


@pytest.fixture
def blockchain_services(
        request,
        deploy_key,
        deploy_client,
        private_keys,
        web3,
):
    return jsonrpc_services(
        deploy_key,
        deploy_client,
        private_keys,
        web3=web3,
    )
