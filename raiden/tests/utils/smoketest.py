import io
import os
import shutil
import sys
import tempfile
import termios
import traceback
from binascii import hexlify, unhexlify
from http import HTTPStatus

import click
import requests
from eth_utils import to_canonical_address, to_checksum_address
from web3 import HTTPProvider, Web3
from web3.middleware import geth_poa_middleware

from raiden.accounts import AccountManager
from raiden.connection_manager import ConnectionManager
from raiden.network.proxies import TokenNetworkRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.utils import get_free_port
from raiden.raiden_service import RaidenService
from raiden.tests.fixtures.variables import DEFAULT_PASSPHRASE
from raiden.tests.integration.contracts.fixtures.contracts import deploy_token
from raiden.tests.utils.geth import (
    GethNodeDescription,
    geth_node_config,
    geth_node_config_set_bootnodes,
    geth_node_to_datadir,
    geth_run_nodes,
    geth_wait_and_check,
)
from raiden.tests.utils.smartcontracts import deploy_contract_web3
from raiden.transfer import channel, views
from raiden.transfer.state import CHANNEL_STATE_OPENED
from raiden.utils import get_project_root, privatekey_to_address
from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    TEST_SETTLE_TIMEOUT_MAX,
    TEST_SETTLE_TIMEOUT_MIN,
)

# the smoketest will assert that a different endpoint got successfully registered
TEST_ENDPOINT = '9.9.9.9:9999'
TEST_PARTNER_ADDRESS = '2' * 40
TEST_DEPOSIT_AMOUNT = 5
CHAIN_ID = 627

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
    url = 'http://localhost:{port}/api/1/channels'.format(port=5001)

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

        token_networks = views.get_token_network_addresses_for(
            views.state_from_raiden(raiden_service),
            raiden_service.default_registry.address,
        )
        assert len(token_networks) == 1

        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden_service),
            raiden_service.default_registry.address,
            token_networks[0],
            unhexlify(TEST_PARTNER_ADDRESS),
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
    except Exception:
        error = traceback.format_exc()
        if debug:
            import pdb
            pdb.post_mortem()  # pylint: disable=no-member
        return error


def start_ethereum():
    ensure_executable(os.environ.setdefault('RST_GETH_BINARY', 'geth'))

    free_port = get_free_port('127.0.0.1', 27854)
    rpc_port = next(free_port)
    p2p_port = next(free_port)
    is_miner = True
    node_key = TEST_PRIVKEY
    base_datadir = os.environ['RST_DATADIR']
    genesis_path = os.path.join(get_project_root(), 'smoketest_genesis.json')

    description = GethNodeDescription(
        node_key,
        rpc_port,
        p2p_port,
        is_miner,
    )

    rpc_endpoint = f'http://127.0.0.1:{rpc_port}'
    web3 = Web3(HTTPProvider(rpc_endpoint))

    verbosity = 0
    geth_nodes = [description]
    random_marker = hexlify(b'raiden').decode()

    config = geth_node_config(
        description.private_key,
        description.p2p_port,
        description.rpc_port,
    )

    if description.miner:
        config['unlock'] = 0
        config['mine'] = True
        config['password'] = os.path.join(base_datadir, 'pw')

    nodes_configuration = [config]
    geth_node_config_set_bootnodes(nodes_configuration)
    keystore = os.path.join(geth_node_to_datadir(config, base_datadir), 'keystore')

    logdir = os.path.join(base_datadir, 'logs')

    # check that the test is running on non-capture mode, and if it is save
    # current term settings before running geth
    if isinstance(sys.stdin, io.IOBase):
        term_settings = termios.tcgetattr(sys.stdin)

    processes_list = geth_run_nodes(
        geth_nodes,
        nodes_configuration,
        base_datadir,
        genesis_path,
        CHAIN_ID,
        verbosity,
        logdir,
    )

    try:
        geth_wait_and_check(web3, [], random_marker)

        for process in processes_list:
            process.poll()

            if process.returncode is not None:
                raise ValueError(f'geth process failed with exit code {process.returncode}')

    except (ValueError, RuntimeError) as e:
        # If geth_wait_and_check or the above loop throw an exception make sure
        # we don't end up with a rogue geth process running in the background
        for process in processes_list:
            process.terminate()
        raise e

    finally:
        # reenter echo mode (disabled by geth pasphrase prompt)
        if isinstance(sys.stdin, io.IOBase):
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, term_settings)

    ethereum_config = {
        'rpc': str(rpc_port),
        'address': to_checksum_address(TEST_ACCOUNT_ADDRESS),
        'init_log_out': b'',
        'init_log_err': b'',
        'password_file': os.path.join(base_datadir, 'pw'),
        'keystore': keystore,
    }
    return processes_list, ethereum_config


def deploy_smoketest_contracts(client, chain_id):
    client.web3.personal.unlockAccount(
        client.web3.eth.accounts[0],
        DEFAULT_PASSPHRASE,
    )

    endpoint_registry_address = deploy_contract_web3(
        CONTRACT_ENDPOINT_REGISTRY,
        client,
        num_confirmations=None,
    )

    secret_registry_address = deploy_contract_web3(
        CONTRACT_SECRET_REGISTRY,
        client,
        num_confirmations=1,
    )

    token_network_registry_address = deploy_contract_web3(
        CONTRACT_TOKEN_NETWORK_REGISTRY,
        client,
        num_confirmations=None,
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


def setup_testchain_and_raiden(transport, matrix_server, print_step):
    print_step('Starting Ethereum node')
    ethereum, ethereum_config = start_ethereum()
    port = ethereum_config['rpc']
    web3_client = Web3(HTTPProvider(f'http://0.0.0.0:{port}'))
    web3_client.middleware_stack.inject(geth_poa_middleware, layer=0)

    print_step('Deploying Raiden contracts')

    client = JSONRPCClient(web3_client, get_private_key(ethereum_config['keystore']))
    contract_addresses = deploy_smoketest_contracts(client, 627)
    token_contract = deploy_token(client)
    token = token_contract(1000, 0, 'TKN', 'TKN')
    registry = TokenNetworkRegistry(client, contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY])
    registry.add_token(to_canonical_address(token.contract.address))

    print_step('Setting up Raiden')
    # setup cli arguments for starting raiden
    args = dict(
        discovery_contract_address=to_checksum_address(
            contract_addresses[CONTRACT_ENDPOINT_REGISTRY],
        ),
        registry_contract_address=to_checksum_address(
            contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY],
        ),
        secret_registry_contract_address=to_checksum_address(
            contract_addresses[CONTRACT_SECRET_REGISTRY],
        ),
        eth_rpc_endpoint='http://127.0.0.1:{}'.format(port),
        keystore_path=ethereum_config['keystore'],
        address=ethereum_config['address'],
        network_id='627',
        sync_check=False,
        transport=transport,
        matrix_server='http://localhost:8008'
                      if matrix_server == 'auto'
                      else matrix_server,
        gas_price='fast',
    )

    args['password_file'] = click.File()(ethereum_config['password_file'])
    args['datadir'] = args['keystore_path']
    return dict(
        args=args,
        contract_addresses=contract_addresses,
        ethereum=ethereum,
        ethereum_config=ethereum_config,
        token=token,
    )
