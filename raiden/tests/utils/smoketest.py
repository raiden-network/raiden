import contextlib
import os
import shutil
import sys
import tempfile
import traceback
from http import HTTPStatus
from typing import IO

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
from raiden.connection_manager import ConnectionManager
from raiden.network.proxies import TokenNetworkRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.utils import get_free_port
from raiden.raiden_service import RaidenService
from raiden.tests.fixtures.variables import DEFAULT_PASSPHRASE
from raiden.tests.utils.eth_node import (
    EthNodeDescription,
    eth_node_config,
    eth_node_config_set_bootnodes,
    eth_node_to_datadir,
    eth_run_nodes,
    eth_wait_and_check,
)
from raiden.tests.utils.smartcontracts import deploy_contract_web3, deploy_token
from raiden.transfer import channel, views
from raiden.transfer.state import CHANNEL_STATE_OPENED
from raiden.utils import get_project_root, privatekey_to_address
from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    NETWORKNAME_TO_ID,
    TEST_SETTLE_TIMEOUT_MAX,
    TEST_SETTLE_TIMEOUT_MIN,
)
from raiden_contracts.contract_manager import ContractManager, contracts_precompiled_path

# the smoketest will assert that a different endpoint got successfully registered
TEST_ENDPOINT = '9.9.9.9:9999'
TEST_PARTNER_ADDRESS = '2' * 40
TEST_DEPOSIT_AMOUNT = 5

TEST_PRIVKEY = (
    b'\xad\xd4\xd3\x10\xba\x04$hy\x1d\xd7\xbf\x7fn\xae\x85\xac'
    b'\xc4\xdd\x14?\xfa\x81\x0e\xf1\x80\x9aj\x11\xf2\xbcD'
)
TEST_ACCOUNT_ADDRESS = privatekey_to_address(TEST_PRIVKEY)

RST_DATADIR = tempfile.mkdtemp()
os.environ['RST_DATADIR'] = RST_DATADIR


def ensure_executable(cmd):
    """look for the given command and make sure it can be executed"""
    if not shutil.which(cmd):
        print(
            'Error: unable to locate %s binary.\n'
            'Make sure it is installed and added to the PATH variable.' % cmd,
        )
        sys.exit(1)


def run_restapi_smoketests():
    """Test if REST api works. """
    url = 'http://localhost:{port}/api/v1/channels'.format(port=5001)

    response = requests.get(url)
    assert response.status_code == HTTPStatus.OK

    response_json = response.json()
    assert (response_json[0]['partner_address'] ==
            to_checksum_address(ConnectionManager.BOOTSTRAP_ADDR))
    assert response_json[0]['state'] == 'opened'
    assert response_json[0]['balance'] > 0


def run_smoketests(
        raiden_service: RaidenService,
        transport: str,
        token_addresses,
        discovery_address,
        orig_stdout: IO[str],
        debug: bool = False,
):
    """ Test that the assembled raiden_service correctly reflects the configuration from the
    smoketest_genesis. """
    try:
        chain = raiden_service.chain
        token_network_added_events = raiden_service.default_registry.filter_token_added_events()
        events_token_addresses = [
            event['args']['token_address']
            for event in token_network_added_events
        ]

        assert events_token_addresses == token_addresses

        if transport == 'udp':
            discovery_addresses = list(chain.address_to_discovery.keys())
            assert len(discovery_addresses) == 1, repr(chain.address_to_discovery)
            assert discovery_addresses[0] == discovery_address
            discovery = chain.address_to_discovery[discovery_addresses[0]]
            assert discovery.endpoint_by_address(raiden_service.address) != TEST_ENDPOINT

        token_networks = views.get_token_identifiers(
            views.state_from_raiden(raiden_service),
            raiden_service.default_registry.address,
        )
        assert len(token_networks) == 1

        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden_service),
            raiden_service.default_registry.address,
            token_networks[0],
            decode_hex(TEST_PARTNER_ADDRESS),
        )

        distributable = channel.get_distributable(
            channel_state.our_state,
            channel_state.partner_state,
        )
        assert distributable == TEST_DEPOSIT_AMOUNT
        assert distributable == channel_state.our_state.contract_balance
        assert channel.get_status(channel_state) == CHANNEL_STATE_OPENED

        # Run API test
        run_restapi_smoketests()
    except:  # NOQA pylint: disable=bare-except
        error = traceback.format_exc()
        if debug:
            with contextlib.redirect_stdout(orig_stdout):
                import pdb
                pdb.post_mortem()  # pylint: disable=no-member
        return error

    return None


def deploy_smoketest_contracts(client, chain_id, contract_manager):
    client.web3.personal.unlockAccount(
        client.web3.eth.accounts[0],
        DEFAULT_PASSPHRASE,
    )

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

    token_network_registry_address = deploy_contract_web3(
        contract_name=CONTRACT_TOKEN_NETWORK_REGISTRY,
        deploy_client=client,
        contract_manager=contract_manager,
        constructor_arguments=(
            to_checksum_address(secret_registry_address),
            chain_id,
            TEST_SETTLE_TIMEOUT_MIN,
            TEST_SETTLE_TIMEOUT_MAX,
        ),
    )

    addresses = {
        CONTRACT_ENDPOINT_REGISTRY: endpoint_registry_address,
        CONTRACT_SECRET_REGISTRY: secret_registry_address,
        CONTRACT_TOKEN_NETWORK_REGISTRY: token_network_registry_address,
    }
    return addresses


def get_private_key(keystore):
    accmgr = AccountManager(keystore)
    if not accmgr.accounts:
        raise RuntimeError("No Ethereum accounts found in the user's system")

    addresses = list(accmgr.accounts.keys())
    return accmgr.get_privkey(addresses[0], DEFAULT_PASSPHRASE)


def setup_testchain_and_raiden(transport, matrix_server, print_step, contracts_version):
    return setup_raiden(
        transport,
        matrix_server,
        print_step,
        contracts_version,
        setup_testchain(print_step),
    )


def setup_testchain(print_step):
    print_step('Starting Ethereum node')

    ensure_executable('geth')

    free_port = get_free_port('127.0.0.1')
    rpc_port = next(free_port)
    p2p_port = next(free_port)
    base_datadir = os.environ['RST_DATADIR']

    description = EthNodeDescription(
        private_key=TEST_PRIVKEY,
        rpc_port=rpc_port,
        p2p_port=p2p_port,
        miner=True,
    )

    eth_rpc_endpoint = f'http://127.0.0.1:{rpc_port}'
    web3 = Web3(HTTPProvider(endpoint_uri=eth_rpc_endpoint))
    web3.middleware_stack.inject(geth_poa_middleware, layer=0)

    config = eth_node_config(
        description.private_key,
        description.p2p_port,
        description.rpc_port,
    )

    config.update({
        'unlock': 0,
        'mine': True,
        'password': os.path.join(base_datadir, 'pw'),
    })

    nodes_configuration = [config]
    eth_node_config_set_bootnodes(nodes_configuration)
    keystore = os.path.join(eth_node_to_datadir(config, base_datadir), 'keystore')

    logdir = os.path.join(base_datadir, 'logs')

    processes_list = eth_run_nodes(
        eth_nodes=[description],
        nodes_configuration=nodes_configuration,
        base_datadir=base_datadir,
        genesis_file=os.path.join(get_project_root(), 'smoketest_genesis.json'),
        chain_id=NETWORKNAME_TO_ID['smoketest'],
        verbosity=0,
        logdir=logdir,
    )

    try:
        # the marker is hardcoded in the genesis file
        random_marker = remove_0x_prefix(encode_hex(b'raiden'))
        eth_wait_and_check(
            web3=web3,
            accounts_addresses=[],
            random_marker=random_marker,
            processes_list=processes_list,
        )
    except (ValueError, RuntimeError) as e:
        # If geth_wait_and_check or the above loop throw an exception make sure
        # we don't end up with a rogue geth process running in the background
        for process in processes_list:
            process.terminate()
        raise e

    return dict(
        base_datadir=base_datadir,
        eth_rpc_endpoint=eth_rpc_endpoint,
        keystore=keystore,
        processes_list=processes_list,
        web3=web3,
    )


def setup_raiden(
        transport,
        matrix_server,
        print_step,
        contracts_version,
        testchain_setup,
):
    print_step('Deploying Raiden contracts')

    client = JSONRPCClient(testchain_setup['web3'], get_private_key(testchain_setup['keystore']))
    contract_manager = ContractManager(
        contracts_precompiled_path(contracts_version),
    )

    contract_addresses = deploy_smoketest_contracts(
        client=client,
        chain_id=NETWORKNAME_TO_ID['smoketest'],
        contract_manager=contract_manager,
    )
    token = deploy_token(
        deploy_client=client,
        contract_manager=contract_manager,
        initial_amount=1000,
        decimals=0,
        token_name='TKN',
        token_symbol='TKN',
    )
    registry = TokenNetworkRegistry(
        jsonrpc_client=client,
        registry_address=contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY],
        contract_manager=contract_manager,
    )
    registry.add_token(
        token_address=to_canonical_address(token.contract.address),
        given_block_identifier='latest',
    )

    print_step('Setting up Raiden')

    endpoint_registry_contract_address = to_checksum_address(
        contract_addresses[CONTRACT_ENDPOINT_REGISTRY],
    )
    tokennetwork_registry_contract_address = to_checksum_address(
        contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY],
    )
    secret_registry_contract_address = to_checksum_address(
        contract_addresses[CONTRACT_SECRET_REGISTRY],
    )
    return {
        'args': {
            'address': to_checksum_address(TEST_ACCOUNT_ADDRESS),
            'datadir': testchain_setup['keystore'],
            'endpoint_registry_contract_address': endpoint_registry_contract_address,
            'eth_rpc_endpoint': testchain_setup['eth_rpc_endpoint'],
            'gas_price': 'fast',
            'keystore_path': testchain_setup['keystore'],
            'matrix_server': matrix_server,
            'network_id': str(NETWORKNAME_TO_ID['smoketest']),
            'password_file': click.File()(os.path.join(testchain_setup['base_datadir'], 'pw')),
            'tokennetwork_registry_contract_address': tokennetwork_registry_contract_address,
            'secret_registry_contract_address': secret_registry_contract_address,
            'sync_check': False,
            'transport': transport,
        },
        'contract_addresses': contract_addresses,
        'ethereum': testchain_setup['processes_list'],
        'token': token,
    }
