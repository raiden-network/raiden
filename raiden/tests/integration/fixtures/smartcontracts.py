from dataclasses import dataclass

import gevent
import pytest
from eth_utils import to_canonical_address
from gevent import Greenlet
from web3.contract import Contract

from raiden.constants import (
    BLOCK_ID_LATEST,
    EMPTY_ADDRESS,
    SECONDS_PER_DAY,
    UINT256_MAX,
    Environment,
)
from raiden.network.proxies.monitoring_service import MonitoringService
from raiden.network.proxies.one_to_n import OneToN
from raiden.network.proxies.proxy_manager import ProxyManager
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.proxies.token import Token
from raiden.network.proxies.token_network import TokenNetwork
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.network.proxies.user_deposit import UserDeposit
from raiden.network.rpc.client import JSONRPCClient
from raiden.settings import MONITORING_REWARD
from raiden.tests.utils.smartcontracts import deploy_token
from raiden.utils.keys import privatekey_to_address
from raiden.utils.typing import (
    Address,
    BlockNumber,
    Callable,
    ChainID,
    List,
    MonitoringServiceAddress,
    OneToNAddress,
    Optional,
    PrivateKey,
    SecretRegistryAddress,
    ServiceRegistryAddress,
    Set,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    UserDepositAddress,
)
from raiden_contracts.constants import (
    CONTRACT_CUSTOM_TOKEN,
    CONTRACT_MONITORING_SERVICE,
    CONTRACT_ONE_TO_N,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_SERVICE_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    CONTRACT_USER_DEPOSIT,
)
from raiden_contracts.contract_manager import ContractManager

RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT = TokenAmount(int(0.075 * 10 ** 18))
RED_EYES_PER_TOKEN_NETWORK_LIMIT = TokenAmount(int(250 * 10 ** 18))


@dataclass
class ServicesSmartContracts:
    utility_token_proxy: Token
    utility_token_network_proxy: Optional[TokenNetwork]
    one_to_n_proxy: OneToN
    user_deposit_proxy: UserDeposit
    service_registry_proxy: ServiceRegistry
    monitoring_service: MonitoringService


@dataclass
class FixtureSmartContracts:
    secret_registry_proxy: SecretRegistry
    token_network_registry_proxy: TokenNetworkRegistry
    token_contracts: List[Contract]
    services_smart_contracts: Optional[ServicesSmartContracts]


def deploy_secret_registry(
    deploy_client: JSONRPCClient, contract_manager: ContractManager, proxy_manager: ProxyManager
) -> SecretRegistry:
    contract, receipt = deploy_client.deploy_single_contract(
        contract_name=CONTRACT_SECRET_REGISTRY,
        contract=contract_manager.get_contract(CONTRACT_SECRET_REGISTRY),
        constructor_parameters=None,
    )

    return proxy_manager.secret_registry(
        SecretRegistryAddress(to_canonical_address(contract.address)),
        BlockNumber(receipt["blockNumber"]),
    )


def deploy_token_network_registry(
    secret_registry_deploy_result: Callable[[], SecretRegistry],
    deploy_client: JSONRPCClient,
    contract_manager: ContractManager,
    proxy_manager: ProxyManager,
    chain_id: ChainID,
    settle_timeout_min: int,
    settle_timeout_max: int,
    max_token_networks: int,
) -> TokenNetworkRegistry:
    secret_registry_proxy = secret_registry_deploy_result()
    contract, receipt = deploy_client.deploy_single_contract(
        contract_name=CONTRACT_TOKEN_NETWORK_REGISTRY,
        contract=contract_manager.get_contract(CONTRACT_TOKEN_NETWORK_REGISTRY),
        constructor_parameters=[
            secret_registry_proxy.address,
            chain_id,
            settle_timeout_min,
            settle_timeout_max,
            max_token_networks,
        ],
    )

    return proxy_manager.token_network_registry(
        TokenNetworkRegistryAddress(to_canonical_address(contract.address)),
        BlockNumber(receipt["blockNumber"]),
    )


def register_token(
    token_network_registry_deploy_result: Callable[[], TokenNetworkRegistry],
    token_deploy_result: Callable[[], Contract],
) -> TokenNetworkAddress:
    token_network_registry_proxy = token_network_registry_deploy_result()
    token_contract = token_deploy_result()

    _, token_network_address = token_network_registry_proxy.add_token(
        token_address=TokenAddress(to_canonical_address(token_contract.address)),
        channel_participant_deposit_limit=RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT,
        token_network_deposit_limit=RED_EYES_PER_TOKEN_NETWORK_LIMIT,
        given_block_identifier=token_contract.web3.eth.block_number,
    )
    return token_network_address


def deploy_service_registry(
    token_deploy_result: Callable[[], Contract],
    deploy_client: JSONRPCClient,
    contract_manager: ContractManager,
    proxy_manager: ProxyManager,
) -> ServiceRegistry:
    token_contract = token_deploy_result()
    contract, receipt = deploy_client.deploy_single_contract(
        contract_name=CONTRACT_SERVICE_REGISTRY,
        contract=contract_manager.get_contract(CONTRACT_SERVICE_REGISTRY),
        constructor_parameters=(
            token_contract.address,
            EMPTY_ADDRESS,
            int(500e18),
            6,
            5,
            180 * SECONDS_PER_DAY,
            1000,
            200 * SECONDS_PER_DAY,
        ),
    )

    return proxy_manager.service_registry(
        ServiceRegistryAddress(to_canonical_address(contract.address)),
        BlockNumber(receipt["blockNumber"]),
    )


def deploy_one_to_n(
    user_deposit_deploy_result: Callable[[], UserDeposit],
    service_registry_deploy_result: Callable[[], ServiceRegistry],
    deploy_client: JSONRPCClient,
    contract_manager: ContractManager,
    proxy_manager: ProxyManager,
    chain_id: ChainID,
) -> OneToN:
    user_deposit_proxy = user_deposit_deploy_result()
    service_registry_proxy = service_registry_deploy_result()
    contract, receipt = deploy_client.deploy_single_contract(
        contract_name=CONTRACT_ONE_TO_N,
        contract=contract_manager.get_contract(CONTRACT_ONE_TO_N),
        constructor_parameters=[
            user_deposit_proxy.address,
            chain_id,
            service_registry_proxy.address,
        ],
    )
    return proxy_manager.one_to_n(
        OneToNAddress(to_canonical_address(contract.address)), BlockNumber(receipt["blockNumber"])
    )


def deploy_monitoring_service(
    token_deploy_result: Callable[[], Contract],
    user_deposit_deploy_result: Callable[[], UserDeposit],
    service_registry_deploy_result: Callable[[], ServiceRegistry],
    token_network_registry_deploy_result: Callable[[], TokenNetworkRegistry],
    deploy_client: JSONRPCClient,
    contract_manager: ContractManager,
    proxy_manager: ProxyManager,
) -> MonitoringService:
    token_contract = token_deploy_result()
    token_network_registry_proxy = token_network_registry_deploy_result()
    user_deposit_proxy = user_deposit_deploy_result()
    service_registry_proxy = service_registry_deploy_result()
    contract, receipt = deploy_client.deploy_single_contract(
        contract_name=CONTRACT_MONITORING_SERVICE,
        contract=contract_manager.get_contract(CONTRACT_MONITORING_SERVICE),
        constructor_parameters=[
            token_contract.address,
            service_registry_proxy.address,
            user_deposit_proxy.address,
            token_network_registry_proxy.address,
        ],
    )
    return proxy_manager.monitoring_service(
        MonitoringServiceAddress(to_canonical_address(contract.address)),
        BlockNumber(receipt["blockNumber"]),
    )


def deploy_user_deposit(
    token_deploy_result: Callable[[], Contract],
    deploy_client: JSONRPCClient,
    contract_manager: ContractManager,
    proxy_manager: ProxyManager,
) -> UserDeposit:
    token_contract = token_deploy_result()
    contract, receipt = deploy_client.deploy_single_contract(
        contract_name=CONTRACT_USER_DEPOSIT,
        contract=contract_manager.get_contract(CONTRACT_USER_DEPOSIT),
        constructor_parameters=[token_contract.address, UINT256_MAX],
    )
    return proxy_manager.user_deposit(
        UserDepositAddress(to_canonical_address(contract.address)),
        BlockNumber(receipt["blockNumber"]),
    )


def transfer_user_deposit_tokens(
    user_deposit_deploy_result: Callable[[], UserDeposit], transfer_to: Address
) -> None:
    user_deposit_proxy = user_deposit_deploy_result()
    user_deposit_proxy.approve_and_deposit(
        beneficiary=transfer_to,
        total_deposit=MONITORING_REWARD,
        given_block_identifier=BLOCK_ID_LATEST,
    )


def fund_node(
    token_result: Callable[[], Contract],
    proxy_manager: ProxyManager,
    to_address: Address,
    amount: TokenAmount,
) -> None:
    token_contract = token_result()
    token_proxy = proxy_manager.token(
        TokenAddress(to_canonical_address(token_contract.address)), BLOCK_ID_LATEST
    )
    token_proxy.transfer(to_address=to_address, amount=amount)


@pytest.fixture
def deploy_smart_contract_bundle_concurrently(
    deploy_client: JSONRPCClient,
    contract_manager: ContractManager,
    proxy_manager: ProxyManager,
    chain_id: ChainID,
    environment_type: Environment,
    max_token_networks: int,
    number_of_tokens: int,
    private_keys: List[PrivateKey],
    register_tokens: bool,
    settle_timeout_max: int,
    settle_timeout_min: int,
    token_amount: TokenAmount,
    token_contract_name: str,
) -> FixtureSmartContracts:

    greenlets: Set[Greenlet] = set()
    participants = [privatekey_to_address(key) for key in private_keys]

    secret_registry_deploy_greenlet = gevent.spawn(
        deploy_secret_registry,
        deploy_client=deploy_client,
        contract_manager=contract_manager,
        proxy_manager=proxy_manager,
    )
    greenlets.add(secret_registry_deploy_greenlet)

    token_network_registry_deploy_greenlet = gevent.spawn(
        deploy_token_network_registry,
        secret_registry_deploy_result=secret_registry_deploy_greenlet.get,
        deploy_client=deploy_client,
        contract_manager=contract_manager,
        proxy_manager=proxy_manager,
        chain_id=chain_id,
        settle_timeout_min=settle_timeout_min,
        settle_timeout_max=settle_timeout_max,
        max_token_networks=max_token_networks,
    )
    greenlets.add(token_network_registry_deploy_greenlet)

    # ERC20 tokens used for token networks
    token_contracts_greenlets = []
    for _ in range(number_of_tokens):
        token_deploy_greenlet = gevent.spawn(
            deploy_token,
            deploy_client=deploy_client,
            contract_manager=contract_manager,
            initial_amount=token_amount,
            decimals=2,
            token_name="raiden",
            token_symbol="Rd",
            token_contract_name=token_contract_name,
        )
        greenlets.add(token_deploy_greenlet)
        token_contracts_greenlets.append(token_deploy_greenlet)

        # Fund the nodes
        for transfer_to in participants:
            fund_node_greenlet = gevent.spawn(
                fund_node,
                token_result=token_deploy_greenlet.get,
                proxy_manager=proxy_manager,
                to_address=transfer_to,
                amount=TokenAmount(token_amount // len(participants)),
            )
            greenlets.add(fund_node_greenlet)

        if register_tokens:
            register_grenlet = gevent.spawn(
                register_token,
                token_deploy_result=token_deploy_greenlet.get,
                token_network_registry_deploy_result=token_network_registry_deploy_greenlet.get,
            )
            greenlets.add(register_grenlet)

        del token_deploy_greenlet

    if environment_type == Environment.DEVELOPMENT:
        utility_token_deploy_greenlet = gevent.spawn(
            deploy_token,
            deploy_client=deploy_client,
            contract_manager=contract_manager,
            initial_amount=TokenAmount(1000 * 10 ** 18),
            decimals=0,
            token_name="TKN",
            token_symbol="TKN",
            token_contract_name=token_contract_name,
        )
        greenlets.add(utility_token_deploy_greenlet)

        if register_tokens:
            register_utility_token_grenlet = gevent.spawn(
                register_token,
                token_deploy_result=utility_token_deploy_greenlet.get,
                token_network_registry_deploy_result=token_network_registry_deploy_greenlet.get,
            )
            greenlets.add(register_utility_token_grenlet)

        service_registry_deploy_greenlet = gevent.spawn(
            deploy_service_registry,
            token_deploy_result=utility_token_deploy_greenlet.get,
            deploy_client=deploy_client,
            contract_manager=contract_manager,
            proxy_manager=proxy_manager,
        )
        greenlets.add(service_registry_deploy_greenlet)

        user_deposit_deploy_greenlet = gevent.spawn(
            deploy_user_deposit,
            token_deploy_result=utility_token_deploy_greenlet.get,
            deploy_client=deploy_client,
            contract_manager=contract_manager,
            proxy_manager=proxy_manager,
        )
        greenlets.add(user_deposit_deploy_greenlet)

        one_to_n_deploy_greenlet = gevent.spawn(
            deploy_one_to_n,
            user_deposit_deploy_result=user_deposit_deploy_greenlet.get,
            service_registry_deploy_result=service_registry_deploy_greenlet.get,
            deploy_client=deploy_client,
            contract_manager=contract_manager,
            proxy_manager=proxy_manager,
            chain_id=chain_id,
        )
        greenlets.add(one_to_n_deploy_greenlet)

        monitoring_service_deploy_greenlet = gevent.spawn(
            deploy_monitoring_service,
            token_deploy_result=utility_token_deploy_greenlet.get,
            user_deposit_deploy_result=user_deposit_deploy_greenlet.get,
            service_registry_deploy_result=service_registry_deploy_greenlet.get,
            token_network_registry_deploy_result=token_network_registry_deploy_greenlet.get,
            deploy_client=deploy_client,
            contract_manager=contract_manager,
            proxy_manager=proxy_manager,
        )
        greenlets.add(monitoring_service_deploy_greenlet)

        for transfer_to in participants:
            transfer_grenlet = gevent.spawn(
                transfer_user_deposit_tokens,
                user_deposit_deploy_result=user_deposit_deploy_greenlet.get,
                transfer_to=transfer_to,
            )
            greenlets.add(transfer_grenlet)

    gevent.joinall(greenlets, raise_error=True)

    secret_registry_proxy = secret_registry_deploy_greenlet.get()
    token_network_registry_proxy = token_network_registry_deploy_greenlet.get()
    token_contracts = [
        token_deploy_greenlet.get() for token_deploy_greenlet in token_contracts_greenlets
    ]

    services_smart_contracts: Optional[ServicesSmartContracts] = None
    if environment_type == Environment.DEVELOPMENT:
        one_to_n_proxy = one_to_n_deploy_greenlet.get()
        user_deposit_proxy = user_deposit_deploy_greenlet.get()
        service_registry_proxy = service_registry_deploy_greenlet.get()
        utility_token_contract = utility_token_deploy_greenlet.get()
        monitoring_service_proxy = monitoring_service_deploy_greenlet.get()

        utility_token_proxy = Token(
            deploy_client, utility_token_contract.address, contract_manager, BLOCK_ID_LATEST
        )

        utility_token_network_proxy: Optional[TokenNetwork] = None
        if register_tokens:
            utility_token_network_address = register_utility_token_grenlet.get()
            utility_token_network_proxy = proxy_manager.token_network(
                utility_token_network_address, BLOCK_ID_LATEST
            )

        services_smart_contracts = ServicesSmartContracts(
            utility_token_proxy=utility_token_proxy,
            utility_token_network_proxy=utility_token_network_proxy,
            one_to_n_proxy=one_to_n_proxy,
            user_deposit_proxy=user_deposit_proxy,
            service_registry_proxy=service_registry_proxy,
            monitoring_service=monitoring_service_proxy,
        )

    return FixtureSmartContracts(
        secret_registry_proxy=secret_registry_proxy,
        token_network_registry_proxy=token_network_registry_proxy,
        token_contracts=token_contracts,
        services_smart_contracts=services_smart_contracts,
    )


@pytest.fixture(name="token_contract_name")
def token_contract_name_fixture() -> str:
    return CONTRACT_CUSTOM_TOKEN


@pytest.fixture(name="max_token_networks")
def max_token_networks_fixture() -> int:
    # Circumvent this condition
    # https://github.com/raiden-network/raiden-contracts/blob/74598401b9ef994eef5e358a78cc176a01c9245d/raiden_contracts/data/source/raiden/TokenNetworkRegistry.sol#L81-L83
    return UINT256_MAX - 1


@pytest.fixture(name="token_addresses")
def token_addresses_fixture(
    deploy_smart_contract_bundle_concurrently: FixtureSmartContracts,
) -> List[TokenAddress]:
    """Fixture that yields `number_of_tokens` ERC20 token addresses, where the
    `token_amount` (per token) is distributed among the addresses behind `deploy_client` and
    potentially pre-registered with the Raiden Registry.
    The following pytest arguments can control the behavior:

    Args:
        token_amount: the overall number of units minted per token
        number_of_tokens: the number of token instances
        register_tokens: controls if tokens will be registered with raiden Registry
    """
    return [
        TokenAddress(to_canonical_address(token.address))
        for token in deploy_smart_contract_bundle_concurrently.token_contracts
    ]


@pytest.fixture(name="secret_registry_address")
def secret_registry_address_fixture(
    deploy_smart_contract_bundle_concurrently: FixtureSmartContracts,
) -> SecretRegistryAddress:
    return deploy_smart_contract_bundle_concurrently.secret_registry_proxy.address


@pytest.fixture(name="service_registry_address")
def service_registry_address_fixture(
    deploy_smart_contract_bundle_concurrently: FixtureSmartContracts,
) -> Optional[ServiceRegistryAddress]:
    services_smart_contracts = deploy_smart_contract_bundle_concurrently.services_smart_contracts
    if services_smart_contracts:
        return services_smart_contracts.service_registry_proxy.address
    return None


@pytest.fixture(name="user_deposit_address")
def user_deposit_address_fixture(
    deploy_smart_contract_bundle_concurrently: FixtureSmartContracts,
) -> Optional[UserDepositAddress]:
    """Deploy UserDeposit and fund accounts with some balances"""
    services_smart_contracts = deploy_smart_contract_bundle_concurrently.services_smart_contracts

    if services_smart_contracts:
        return services_smart_contracts.user_deposit_proxy.address

    return None


@pytest.fixture(name="one_to_n_address")
def one_to_n_address_fixture(
    deploy_smart_contract_bundle_concurrently: FixtureSmartContracts,
) -> Optional[OneToNAddress]:
    """Deploy OneToN contract and return the address"""
    services_smart_contracts = deploy_smart_contract_bundle_concurrently.services_smart_contracts

    if services_smart_contracts:
        return services_smart_contracts.one_to_n_proxy.address

    return None


@pytest.fixture(name="monitoring_service_address")
def monitoring_service_address_fixture(
    deploy_smart_contract_bundle_concurrently: FixtureSmartContracts,
) -> Optional[MonitoringServiceAddress]:
    """Deploy OneToN contract and return the address"""
    services_smart_contracts = deploy_smart_contract_bundle_concurrently.services_smart_contracts

    if services_smart_contracts:
        return services_smart_contracts.monitoring_service.address

    return None


@pytest.fixture(name="secret_registry_proxy")
def secret_registry_proxy_fixture(
    deploy_client: JSONRPCClient,
    secret_registry_address: SecretRegistryAddress,
    contract_manager: ContractManager,
) -> SecretRegistry:
    """This uses the available SecretRegistry JSONRPCClient proxy to
    instantiate a Raiden proxy.

    The JSONRPCClient proxy just exposes the functions from the smart contract
    as methods in a generate python object, the Raiden proxy uses it to
    provider alternative interfaces *and* most importantly to do additional
    error checking (reason for transaction failure, gas usage, etc.).
    """
    return SecretRegistry(
        jsonrpc_client=deploy_client,
        secret_registry_address=secret_registry_address,
        contract_manager=contract_manager,
        block_identifier=BLOCK_ID_LATEST,
    )


@pytest.fixture(name="token_network_registry_address")
def token_network_registry_address_fixture(
    deploy_smart_contract_bundle_concurrently: FixtureSmartContracts,
) -> TokenNetworkRegistryAddress:
    return deploy_smart_contract_bundle_concurrently.token_network_registry_proxy.address


@pytest.fixture(name="token_network_proxy")
def token_network_proxy_fixture(
    deploy_smart_contract_bundle_concurrently: FixtureSmartContracts,
) -> Optional[TokenNetwork]:

    services_smart_contracts = deploy_smart_contract_bundle_concurrently.services_smart_contracts

    if services_smart_contracts:
        return services_smart_contracts.utility_token_network_proxy

    return None


@pytest.fixture(name="token_proxy")
def token_proxy_fixture(
    deploy_smart_contract_bundle_concurrently: FixtureSmartContracts, environment_type: Environment
) -> Token:
    msg = "environment_type must be set to DEVELOPMENT"
    assert environment_type == Environment.DEVELOPMENT, msg

    services_smart_contracts = deploy_smart_contract_bundle_concurrently.services_smart_contracts
    assert services_smart_contracts, msg
    return services_smart_contracts.utility_token_proxy
