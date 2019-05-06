import contextlib
import os
import shutil
import signal
import sys
import tempfile
import traceback
from contextlib import contextmanager
from copy import deepcopy
from http import HTTPStatus
from io import StringIO
from subprocess import TimeoutExpired
from typing import Any, Callable, ContextManager, List

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
from raiden.app import App
from raiden.connection_manager import ConnectionManager
from raiden.constants import (
    RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT,
    RED_EYES_PER_TOKEN_NETWORK_LIMIT,
    UINT256_MAX,
    EthClient,
    RoutingMode,
)
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.raiden_service import RaidenService
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS, DEVELOPMENT_CONTRACT_VERSION
from raiden.tests.fixtures.constants import DEFAULT_PASSPHRASE
from raiden.tests.utils.eth_node import (
    EthNodeDescription,
    GenesisDescription,
    eth_node_config,
    eth_node_to_datadir,
    eth_run_nodes,
    geth_generate_poa_genesis,
    parity_create_account,
    parity_generate_chain_spec,
)
from raiden.tests.utils.smartcontracts import deploy_contract_web3, deploy_token
from raiden.transfer import channel, views
from raiden.transfer.state import CHANNEL_STATE_OPENED
from raiden.ui.app import run_app
from raiden.utils import merge_dict, privatekey_to_address, split_endpoint
from raiden.utils.http import HTTPExecutor
from raiden.utils.typing import Address, AddressHex, ChainID, Dict, Iterator
from raiden.waiting import wait_for_block
from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_SERVICE_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    NETWORKNAME_TO_ID,
    TEST_SETTLE_TIMEOUT_MAX,
    TEST_SETTLE_TIMEOUT_MIN,
)
from raiden_contracts.contract_manager import ContractManager, contracts_precompiled_path

# the smoketest will assert that a different endpoint got successfully registered
TEST_ENDPOINT = "9.9.9.9:9999"
TEST_PARTNER_ADDRESS = "2" * 40
TEST_DEPOSIT_AMOUNT = 5

TEST_PRIVKEY = (
    b"\xad\xd4\xd3\x10\xba\x04$hy\x1d\xd7\xbf\x7fn\xae\x85\xac"
    b"\xc4\xdd\x14?\xfa\x81\x0e\xf1\x80\x9aj\x11\xf2\xbcD"
)
TEST_ACCOUNT_ADDRESS = privatekey_to_address(TEST_PRIVKEY)

RST_DATADIR = tempfile.mkdtemp()
os.environ["RST_DATADIR"] = RST_DATADIR


def ensure_executable(cmd):
    """look for the given command and make sure it can be executed"""
    if not shutil.which(cmd):
        print(
            "Error: unable to locate %s binary.\n"
            "Make sure it is installed and added to the PATH variable." % cmd
        )
        sys.exit(1)


def run_restapi_smoketests(port_number):
    """Test if REST api works. """
    url = "http://localhost:{port}/api/v1/channels".format(port=port_number)

    response = requests.get(url)
    assert response.status_code == HTTPStatus.OK

    response_json = response.json()
    assert response_json[0]["partner_address"] == to_checksum_address(
        ConnectionManager.BOOTSTRAP_ADDR
    )
    assert response_json[0]["state"] == "opened"
    assert response_json[0]["balance"] > 0


def smoketest_perform_tests(
    raiden_service: RaidenService, transport: str, token_addresses, discovery_address
):
    """ Perform high level tests designed to quickly discover broken functionality. """
    try:
        chain = raiden_service.chain
        token_network_added_events = raiden_service.default_registry.filter_token_added_events()
        events_token_addresses = [
            event["args"]["token_address"] for event in token_network_added_events
        ]

        assert events_token_addresses == token_addresses

        if transport == "udp":
            discovery_addresses = list(chain.address_to_discovery.keys())
            assert len(discovery_addresses) == 1, repr(chain.address_to_discovery)
            assert discovery_addresses[0] == discovery_address
            discovery = chain.address_to_discovery[discovery_addresses[0]]
            assert discovery.endpoint_by_address(raiden_service.address) != TEST_ENDPOINT

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
        assert channel.get_status(channel_state) == CHANNEL_STATE_OPENED

        # Run API test
        run_restapi_smoketests(raiden_service.config["api_port"])
    except:  # NOQA pylint: disable=bare-except
        error = traceback.format_exc()
        return error

    return None


def deploy_smoketest_contracts(
    client: JSONRPCClient,
    chain_id: ChainID,
    contract_manager: ContractManager,
    token_address: AddressHex,
) -> Dict[str, Address]:
    client.web3.personal.unlockAccount(client.web3.eth.accounts[0], DEFAULT_PASSPHRASE)

    endpoint_registry_address = deploy_contract_web3(
        contract_name=CONTRACT_ENDPOINT_REGISTRY,
        deploy_client=client,
        contract_manager=contract_manager,
    )

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
        CONTRACT_ENDPOINT_REGISTRY: endpoint_registry_address,
        CONTRACT_SECRET_REGISTRY: secret_registry_address,
        CONTRACT_TOKEN_NETWORK_REGISTRY: token_network_registry_address,
    }
    if contract_manager.contracts_version == DEVELOPMENT_CONTRACT_VERSION:
        service_registry_address = deploy_contract_web3(
            contract_name=CONTRACT_SERVICE_REGISTRY,
            deploy_client=client,
            contract_manager=contract_manager,
            constructor_arguments=(token_address,),
        )
        addresses[CONTRACT_SERVICE_REGISTRY] = service_registry_address
    return addresses


def get_private_key(keystore):
    accmgr = AccountManager(keystore)
    if not accmgr.accounts:
        raise RuntimeError("No Ethereum accounts found in the user's system")

    addresses = list(accmgr.accounts.keys())
    return accmgr.get_privkey(addresses[0], DEFAULT_PASSPHRASE)


@contextmanager
def setup_testchain_and_raiden(
    transport: str,
    eth_client: EthClient,
    matrix_server: str,
    contracts_version: str,
    print_step: Callable,
    free_port_generator: Iterator[int],
):
    testchain_manager = setup_testchain(
        eth_client=eth_client, print_step=print_step, free_port_generator=free_port_generator
    )
    with testchain_manager as testchain:
        yield setup_raiden(transport, matrix_server, print_step, contracts_version, testchain)


@contextmanager
def setup_testchain(
    eth_client: EthClient, print_step: Callable, free_port_generator: Iterator[int]
) -> ContextManager[Dict[str, Any]]:
    # TODO: This has a lot of overlap with `raiden.tests.utils.eth_node.run_private_blockchain` -
    #       refactor into a unified utility
    print_step("Starting Ethereum node")

    ensure_executable(eth_client.value)

    rpc_port = next(free_port_generator)
    p2p_port = next(free_port_generator)
    base_datadir = os.environ["RST_DATADIR"]

    description = EthNodeDescription(
        private_key=TEST_PRIVKEY,
        rpc_port=rpc_port,
        p2p_port=p2p_port,
        miner=True,
        extra_config={},
        blockchain_type=eth_client.value,
    )

    eth_rpc_endpoint = f"http://127.0.0.1:{rpc_port}"
    web3 = Web3(HTTPProvider(endpoint_uri=eth_rpc_endpoint))
    web3.middleware_stack.inject(geth_poa_middleware, layer=0)

    config = eth_node_config(description.private_key, description.p2p_port, description.rpc_port)

    config.update({"unlock": 0, "mine": True, "password": os.path.join(base_datadir, "pw")})

    nodes_configuration = [config]
    logdir = os.path.join(base_datadir, "logs")

    # the marker is hardcoded in the genesis file
    random_marker = remove_0x_prefix(encode_hex(b"raiden"))
    seal_account = privatekey_to_address(description.private_key)
    accounts_to_fund = [TEST_ACCOUNT_ADDRESS, TEST_PARTNER_ADDRESS]

    genesis_description = GenesisDescription(
        prefunded_accounts=accounts_to_fund,
        random_marker=random_marker,
        chain_id=NETWORKNAME_TO_ID["smoketest"],
    )

    if eth_client is EthClient.GETH:
        keystore = os.path.join(eth_node_to_datadir(config, base_datadir), "keystore")
        genesis_path = os.path.join(base_datadir, "custom_genesis.json")
        geth_generate_poa_genesis(
            genesis_path=genesis_path,
            genesis_description=genesis_description,
            seal_account=seal_account,
        )
    elif eth_client is EthClient.PARITY:
        genesis_path = f"{base_datadir}/chainspec.json"
        parity_generate_chain_spec(
            genesis_path=genesis_path,
            genesis_description=genesis_description,
            seal_account=seal_account,
        )
        keystore = parity_create_account(nodes_configuration[0], base_datadir, genesis_path)
    else:
        raise RuntimeError(f"Invalid eth client type: {eth_client.value}")

    node_runner = eth_run_nodes(
        eth_node_descs=[description],
        nodes_configuration=nodes_configuration,
        base_datadir=base_datadir,
        genesis_file=genesis_path,
        chain_id=NETWORKNAME_TO_ID["smoketest"],
        random_marker=random_marker,
        verbosity="info",
        logdir=logdir,
    )
    with node_runner as node_executors:
        yield dict(
            eth_client=eth_client,
            base_datadir=base_datadir,
            eth_rpc_endpoint=eth_rpc_endpoint,
            keystore=keystore,
            node_executors=node_executors,
            web3=web3,
        )


def setup_raiden(transport, matrix_server, print_step, contracts_version, testchain_setup):
    print_step("Deploying Raiden contracts")

    if testchain_setup["eth_client"] is EthClient.PARITY:
        client = JSONRPCClient(
            testchain_setup["web3"],
            get_private_key(testchain_setup["keystore"]),
            gas_estimate_correction=lambda gas: gas * 2,
        )
    else:
        client = JSONRPCClient(
            testchain_setup["web3"], get_private_key(testchain_setup["keystore"])
        )
    contract_manager = ContractManager(contracts_precompiled_path(contracts_version))

    token = deploy_token(
        deploy_client=client,
        contract_manager=contract_manager,
        initial_amount=1000,
        decimals=0,
        token_name="TKN",
        token_symbol="TKN",
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
    endpoint_registry_contract_address = to_checksum_address(
        contract_addresses[CONTRACT_ENDPOINT_REGISTRY]
    )
    tokennetwork_registry_contract_address = to_checksum_address(
        contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY]
    )
    secret_registry_contract_address = to_checksum_address(
        contract_addresses[CONTRACT_SECRET_REGISTRY]
    )

    args = {
        "address": to_checksum_address(TEST_ACCOUNT_ADDRESS),
        "datadir": testchain_setup["keystore"],
        "endpoint_registry_contract_address": endpoint_registry_contract_address,
        "eth_rpc_endpoint": testchain_setup["eth_rpc_endpoint"],
        "gas_price": "fast",
        "keystore_path": testchain_setup["keystore"],
        "matrix_server": matrix_server,
        "network_id": str(NETWORKNAME_TO_ID["smoketest"]),
        "password_file": click.File()(os.path.join(testchain_setup["base_datadir"], "pw")),
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

    return {
        "args": args,
        "contract_addresses": contract_addresses,
        "ethereum_nodes": testchain_setup["node_executors"],
        "token": token,
    }


def run_smoketest(
    print_step: Callable,
    append_report: Callable,
    args: Dict[str, Any],
    contract_addresses: List[Address],
    token: ContractProxy,
    debug: bool,
    ethereum_nodes: List[HTTPExecutor],
):
    print_step("Starting Raiden")

    config = deepcopy(App.DEFAULT_CONFIG)
    extra_config = args.pop("extra_config", None)
    if extra_config:
        merge_dict(config, extra_config)
    args["config"] = config
    # Should use basic routing in the smoke test for now
    # TODO: If we ever utilize a PFS in the smoke test we
    # need to use the deployed service registry, register the
    # PFS service there and then change this argument.
    args["routing_mode"] = RoutingMode.BASIC

    raiden_stdout = StringIO()
    maybe_redirect_stdout = contextlib.redirect_stdout(raiden_stdout)
    if debug:
        maybe_redirect_stdout = contextlib.nullcontext()
    with maybe_redirect_stdout:
        success = False
        app = None
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
            error = smoketest_perform_tests(
                app.raiden,
                args["transport"],
                token_addresses,
                contract_addresses[CONTRACT_ENDPOINT_REGISTRY],
            )
            if error is not None:
                append_report("Smoketest assertion error", error)
            else:
                success = True
        except:  # noqa pylint: disable=bare-except
            if debug:
                import pdb

                # The pylint comment is required when pdbpp is installed
                pdb.post_mortem()  # pylint: disable=no-member
            else:
                error = traceback.format_exc()
                append_report("Smoketest execution error", error)
        finally:
            if app is not None:
                app.stop()
                app.raiden.get()
            node_executor = ethereum_nodes[0]
            node = node_executor.process
            node.send_signal(signal.SIGINT)
            try:
                node.wait(10)
            except TimeoutExpired:
                print_step("Ethereum node shutdown unclean, check log!", error=True)
                node.kill()

            if isinstance(node_executor.stdio, tuple):
                logfile = node_executor.stdio[1]
                logfile.flush()
                logfile.seek(0)
                append_report("Ethereum Node log output", logfile.read())
    append_report("Raiden Node stdout", raiden_stdout.getvalue())
    if success:
        print_step(f"Smoketest successful")
    else:
        print_step(f"Smoketest had errors", error=True)
    return success
