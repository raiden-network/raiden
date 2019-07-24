import json
import os
import random
import shutil
import sys
from contextlib import contextmanager
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Callable, ContextManager, List

import click
import requests
from eth_utils import (
    decode_hex,
    encode_hex,
    remove_0x_prefix,
    to_canonical_address,
    to_checksum_address,
)
from web3 import HTTPProvider, Web3
from web3.middleware import geth_poa_middleware

from raiden.accounts import AccountManager
from raiden.api.python import RaidenAPI
from raiden.api.rest import APIServer, RestAPI
from raiden.connection_manager import ConnectionManager
from raiden.constants import (
    EMPTY_ADDRESS,
    RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT,
    RED_EYES_PER_TOKEN_NETWORK_LIMIT,
    SECONDS_PER_DAY,
    UINT256_MAX,
    EthClient,
)
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS, DEVELOPMENT_CONTRACT_VERSION
from raiden.tests.fixtures.constants import DEFAULT_BALANCE, DEFAULT_PASSPHRASE
from raiden.tests.utils.eth_node import (
    AccountDescription,
    EthNodeDescription,
    GenesisDescription,
    eth_node_to_datadir,
    geth_keystore,
    parity_keystore,
    run_private_blockchain,
)
from raiden.tests.utils.smartcontracts import deploy_contract_web3, deploy_token
from raiden.transfer import channel, views
from raiden.transfer.state import ChannelState
from raiden.ui.app import run_app
from raiden.utils import privatekey_to_address, split_endpoint
from raiden.utils.typing import Address, AddressHex, ChainID, Dict, Iterable, Port
from raiden.waiting import wait_for_block
from raiden_contracts.constants import (
    CONTRACT_HUMAN_STANDARD_TOKEN,
    CONTRACT_MONITORING_SERVICE,
    CONTRACT_ONE_TO_N,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_SERVICE_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    NETWORKNAME_TO_ID,
    TEST_SETTLE_TIMEOUT_MAX,
    TEST_SETTLE_TIMEOUT_MIN,
)
from raiden_contracts.contract_manager import ContractManager, contracts_precompiled_path

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.network.transport.matrix import ParsedURL  # noqa: F401

# the smoketest will assert that a different endpoint got successfully registered
TEST_PARTNER_ADDRESS = "2" * 40
TEST_DEPOSIT_AMOUNT = 5

TEST_PRIVKEY = (
    b"\xad\xd4\xd3\x10\xba\x04$hy\x1d\xd7\xbf\x7fn\xae\x85\xac"
    b"\xc4\xdd\x14?\xfa\x81\x0e\xf1\x80\x9aj\x11\xf2\xbcD"
)
TEST_ACCOUNT_ADDRESS = privatekey_to_address(TEST_PRIVKEY)


def ensure_executable(cmd):
    """look for the given command and make sure it can be executed"""
    if not shutil.which(cmd):
        print(
            "Error: unable to locate %s binary.\n"
            "Make sure it is installed and added to the PATH variable." % cmd
        )
        sys.exit(1)


def deploy_smoketest_contracts(
    client: JSONRPCClient,
    chain_id: ChainID,
    contract_manager: ContractManager,
    token_address: AddressHex,
) -> Dict[str, Address]:
    client.web3.personal.unlockAccount(client.web3.eth.accounts[0], DEFAULT_PASSPHRASE)

    secret_registry_address = deploy_contract_web3(
        contract_name=CONTRACT_SECRET_REGISTRY,
        deploy_client=client,
        contract_manager=contract_manager,
    )
    constructor_arguments = [
        to_checksum_address(secret_registry_address),
        chain_id,
        TEST_SETTLE_TIMEOUT_MIN,
        TEST_SETTLE_TIMEOUT_MAX,
    ]

    if contract_manager.contracts_version == DEVELOPMENT_CONTRACT_VERSION:
        constructor_arguments.append(UINT256_MAX)

    token_network_registry_address = deploy_contract_web3(
        contract_name=CONTRACT_TOKEN_NETWORK_REGISTRY,
        deploy_client=client,
        contract_manager=contract_manager,
        constructor_arguments=constructor_arguments,
    )

    addresses = {
        CONTRACT_SECRET_REGISTRY: secret_registry_address,
        CONTRACT_TOKEN_NETWORK_REGISTRY: token_network_registry_address,
    }
    if contract_manager.contracts_version == DEVELOPMENT_CONTRACT_VERSION:
        service_registry_address = deploy_contract_web3(
            contract_name=CONTRACT_SERVICE_REGISTRY,
            deploy_client=client,
            contract_manager=contract_manager,
            constructor_arguments=(
                token_address,
                EMPTY_ADDRESS,
                int(500e18),
                6,
                5,
                180 * SECONDS_PER_DAY,
                1000,
                200 * SECONDS_PER_DAY,
            ),
        )
        addresses[CONTRACT_SERVICE_REGISTRY] = service_registry_address

        # The MSC is not used, no need to waste time on deployment
        addresses[CONTRACT_MONITORING_SERVICE] = "0x" + "1" * 40
        # The OneToN contract is not used, no need to waste time on deployment
        addresses[CONTRACT_ONE_TO_N] = "0x" + "1" * 40

    return addresses


def get_private_key(keystore):
    accmgr = AccountManager(keystore)
    if not accmgr.accounts:
        raise RuntimeError("No Ethereum accounts found in the user's system")

    addresses = list(accmgr.accounts.keys())
    return accmgr.get_privkey(addresses[0], DEFAULT_PASSPHRASE)


@contextmanager
def setup_testchain(
    eth_client: EthClient, free_port_generator: Iterable[Port], base_datadir: str, base_logdir: str
) -> ContextManager[Dict[str, Any]]:

    ensure_executable(eth_client.value)

    rpc_port = next(free_port_generator)
    p2p_port = next(free_port_generator)

    eth_rpc_endpoint = f"http://127.0.0.1:{rpc_port}"
    web3 = Web3(HTTPProvider(endpoint_uri=eth_rpc_endpoint))
    web3.middleware_stack.inject(geth_poa_middleware, layer=0)

    eth_nodes = [
        EthNodeDescription(
            private_key=TEST_PRIVKEY,
            rpc_port=rpc_port,
            p2p_port=p2p_port,
            miner=True,
            extra_config={},
            blockchain_type=eth_client.value,
        )
    ]

    random_marker = remove_0x_prefix(hex(random.getrandbits(100)))
    genesis_description = GenesisDescription(
        prefunded_accounts=[
            AccountDescription(TEST_ACCOUNT_ADDRESS, DEFAULT_BALANCE),
            AccountDescription(TEST_PARTNER_ADDRESS, DEFAULT_BALANCE),
        ],
        random_marker=random_marker,
        chain_id=NETWORKNAME_TO_ID["smoketest"],
    )

    nodekeyhex = remove_0x_prefix(encode_hex(TEST_PRIVKEY))
    datadir = eth_node_to_datadir(nodekeyhex, base_datadir)
    if eth_client is EthClient.GETH:
        keystore = geth_keystore(datadir)
    elif eth_client is EthClient.PARITY:
        keystore = parity_keystore(datadir)

    eth_node_runner = run_private_blockchain(
        web3=web3,
        eth_nodes=eth_nodes,
        base_datadir=base_datadir,
        log_dir=base_logdir,
        verbosity="info",
        genesis_description=genesis_description,
    )
    with eth_node_runner as node_executors:
        yield dict(
            eth_client=eth_client,
            base_datadir=base_datadir,
            eth_rpc_endpoint=eth_rpc_endpoint,
            keystore=keystore,
            node_executors=node_executors,
            web3=web3,
        )


@contextmanager
def setup_matrix_for_smoketest(
    print_step: Callable, free_port_generator: Iterable[Port]
) -> ContextManager[List["ParsedURL"]]:
    from raiden.tests.utils.transport import matrix_server_starter

    print_step("Starting Matrix transport")

    with matrix_server_starter(free_port_generator=free_port_generator) as ctx:
        yield ctx


@contextmanager
def setup_testchain_for_smoketest(
    eth_client: EthClient,
    print_step: Callable,
    free_port_generator: Iterable[Port],
    base_datadir: str,
    base_logdir: str,
) -> ContextManager[Dict[str, Any]]:
    print_step("Starting Ethereum node")

    with setup_testchain(
        eth_client=eth_client,
        free_port_generator=free_port_generator,
        base_datadir=base_datadir,
        base_logdir=base_logdir,
    ) as ctx:
        yield ctx


def setup_raiden(
    transport,
    matrix_server,
    print_step,
    contracts_version,
    eth_client,
    eth_rpc_endpoint,
    web3,
    base_datadir,
    keystore,
):
    print_step("Deploying Raiden contracts")

    if eth_client is EthClient.PARITY:
        client = JSONRPCClient(
            web3, get_private_key(keystore), gas_estimate_correction=lambda gas: gas * 2
        )
    else:
        client = JSONRPCClient(web3, get_private_key(keystore))
    contract_manager = ContractManager(contracts_precompiled_path(contracts_version))

    blockchain_service = BlockChainService(
        jsonrpc_client=client, contract_manager=contract_manager
    )

    token = deploy_token(
        deploy_client=client,
        contract_manager=contract_manager,
        initial_amount=1000,
        decimals=0,
        token_name="TKN",
        token_symbol="TKN",
        token_contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
    )
    contract_addresses = deploy_smoketest_contracts(
        client=client,
        chain_id=NETWORKNAME_TO_ID["smoketest"],
        contract_manager=contract_manager,
        token_address=to_canonical_address(token.contract.address),
    )
    registry = TokenNetworkRegistry(
        jsonrpc_client=client,
        registry_address=contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY],
        contract_manager=contract_manager,
        blockchain_service=blockchain_service,
    )

    if contracts_version == DEVELOPMENT_CONTRACT_VERSION:
        registry.add_token_with_limits(
            token_address=to_canonical_address(token.contract.address),
            channel_participant_deposit_limit=RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT,
            token_network_deposit_limit=RED_EYES_PER_TOKEN_NETWORK_LIMIT,
        )
    else:
        registry.add_token_without_limits(
            token_address=to_canonical_address(token.contract.address)
        )

    print_step("Setting up Raiden")
    tokennetwork_registry_contract_address = to_checksum_address(
        contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY]
    )
    secret_registry_contract_address = to_checksum_address(
        contract_addresses[CONTRACT_SECRET_REGISTRY]
    )

    args = {
        "address": to_checksum_address(TEST_ACCOUNT_ADDRESS),
        "datadir": keystore,
        "eth_rpc_endpoint": eth_rpc_endpoint,
        "gas_price": "fast",
        "keystore_path": keystore,
        "matrix_server": matrix_server,
        "network_id": str(NETWORKNAME_TO_ID["smoketest"]),
        "password_file": click.File()(os.path.join(base_datadir, "pw")),
        "tokennetwork_registry_contract_address": tokennetwork_registry_contract_address,
        "secret_registry_contract_address": secret_registry_contract_address,
        "sync_check": False,
        "transport": transport,
    }

    if contracts_version == DEVELOPMENT_CONTRACT_VERSION:
        service_registry_contract_address = to_checksum_address(
            contract_addresses[CONTRACT_SERVICE_REGISTRY]
        )
        args["service_registry_contract_address"] = service_registry_contract_address

        monitoring_service_contract_address = to_checksum_address(
            contract_addresses[CONTRACT_MONITORING_SERVICE]
        )
        args["monitoring_service_contract_address"] = monitoring_service_contract_address

        one_to_n_contract_address = to_checksum_address(contract_addresses[CONTRACT_ONE_TO_N])
        args["one_to_n_contract_address"] = one_to_n_contract_address

    return {"args": args, "contract_addresses": contract_addresses, "token": token}


def run_smoketest(
    print_step: Callable,
    args: Dict[str, Any],
    contract_addresses: List[Address],
    token: ContractProxy,
):
    print_step("Starting Raiden")

    app = None
    api_server = None
    try:
        app = run_app(**args)
        raiden_api = RaidenAPI(app.raiden)
        rest_api = RestAPI(raiden_api)
        (api_host, api_port) = split_endpoint(args["api_address"])
        api_server = APIServer(rest_api, config={"host": api_host, "port": api_port})
        api_server.start()

        block = app.raiden.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
        # Proxies now use the confirmed block hash to query the chain for
        # prerequisite checks. Wait a bit here to make sure that the confirmed
        # block hash contains the deployed token network or else things break
        wait_for_block(raiden=app.raiden, block_number=block, retry_timeout=1.0)

        raiden_api.channel_open(
            registry_address=contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY],
            token_address=to_canonical_address(token.contract.address),
            partner_address=to_canonical_address(TEST_PARTNER_ADDRESS),
        )
        raiden_api.set_total_channel_deposit(
            contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY],
            to_canonical_address(token.contract.address),
            to_canonical_address(TEST_PARTNER_ADDRESS),
            TEST_DEPOSIT_AMOUNT,
        )
        token_addresses = [to_checksum_address(token.contract.address)]

        print_step("Running smoketest")

        raiden_service = app.raiden
        token_network_added_events = raiden_service.default_registry.filter_token_added_events()
        events_token_addresses = [
            event["args"]["token_address"] for event in token_network_added_events
        ]

        assert events_token_addresses == token_addresses

        token_networks = views.get_token_identifiers(
            views.state_from_raiden(raiden_service), raiden_service.default_registry.address
        )
        assert len(token_networks) == 1

        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden_service),
            raiden_service.default_registry.address,
            token_networks[0],
            decode_hex(TEST_PARTNER_ADDRESS),
        )

        distributable = channel.get_distributable(
            channel_state.our_state, channel_state.partner_state
        )
        assert distributable == TEST_DEPOSIT_AMOUNT
        assert distributable == channel_state.our_state.contract_balance
        assert channel.get_status(channel_state) == ChannelState.STATE_OPENED

        port_number = raiden_service.config["api_port"]
        response = requests.get(f"http://localhost:{port_number}/api/v1/channels")

        assert response.status_code == HTTPStatus.OK

        response_json = json.loads(response.content)
        assert response_json[0]["partner_address"] == to_checksum_address(
            ConnectionManager.BOOTSTRAP_ADDR
        )
        assert response_json[0]["state"] == "opened"
        assert response_json[0]["balance"] > 0
    finally:
        if api_server is not None:
            api_server.stop()
            api_server.get()

        if app is not None:
            app.stop()
            app.raiden.get()
