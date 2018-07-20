import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from binascii import hexlify, unhexlify
from http import HTTPStatus
from string import Template
from typing import Dict

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
from raiden.tests.integration.contracts.fixtures.contracts import deploy_token
from raiden.tests.utils.geth import geth_wait_and_check
from raiden.tests.utils.smartcontracts import deploy_contract_web3
from raiden.transfer import channel, views
from raiden.transfer.state import CHANNEL_STATE_OPENED
from raiden.utils import get_project_root
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

RST_DATADIR = tempfile.mkdtemp()
os.environ['RST_DATADIR'] = RST_DATADIR

GENESIS_PATH = Template('$RST_DATADIR/genesis.json').substitute(os.environ)

# Environment variables in the command for datadir and ports allow customization.
# We use DEFAULT_ETH_COMMAND, unless '$RST_ETH_COMMAND' is defined (all environment variables
# specific to the raiden smoke test are prefixed 'RST_' for Raiden Smoke Test).
# For customization, set the environment variable to fit your client like this:
# RST_ETH_COMMAND="ethereum --rpc-port \$RST_RPC_PORT \
#        --data-dir \$RST_DATADIR" raiden smoketest
# FIXME: this does not work: the `init` phase is not customizable (gh issue #758)
DEFAULT_ETH_COMMAND = """
$RST_GETH_BINARY
    --nodiscover
    --nat none
    --port 0
    --ipcdisable
    --rpc
    --rpcaddr 127.0.0.1
    --rpcapi eth,net,web3,personal
    --rpcport $RST_RPC_PORT
    --mine
    --etherbase 0
    --unlock 0
    --networkid 627
    --verbosity 3
    --datadir $RST_DATADIR
"""


def ensure_executable(cmd):
    """look for the given command and make sure it can be executed"""
    if not shutil.which(cmd):
        print(
            'Error: unable to locate %s binary.\n'
            'Make sure it is installed and added to the PATH variable.' % cmd,
        )
        sys.exit(1)


TEST_ACCOUNT = {
    'version': 3,
    'crypto': {
        'ciphertext': '4d9fecf81ca312f7b1ee1bd57196e9c51737d461d7faa019f566834d4d3d4615',
        'cipherparams': {
            'iv': 'd19d1a6a1a66fb8d86755eeee0cc5da8',
        },
        'kdf': 'pbkdf2',
        'kdfparams': {
            'dklen': 32,
            'c': 262144,
            'prf': 'hmac-sha256',
            'salt': '6725f3e185b3f0475e52507e512b1b2c',
        },
        'mac': 'ec86b1e6188dc2e7e415fa4214153636387338dbffe2edf1b04fac6be23eead4',
        'cipher': 'aes-128-ctr',
        'version': 1,
    },
    'address': '67a5e21e34a58ed8d47c719fe291ddd2ea825e12',
}
TEST_ACCOUNT_PASSWORD = 'password'
TEST_PRIVKEY = 'add4d310ba042468791dd7bf7f6eae85acc4dd143ffa810ef1809a6a11f2bc44'


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


def run_smoketests(raiden_service: RaidenService, test_config: Dict, debug: bool = False):
    """ Test that the assembled raiden_service correctly reflects the configuration from the
    smoketest_genesis. """
    try:
        chain = raiden_service.chain
        assert (
            raiden_service.default_registry.address ==
            to_canonical_address(test_config['contracts']['registry_address'])
        )
        assert (
            raiden_service.default_secret_registry.address ==
            to_canonical_address(test_config['contracts']['secret_registry_address'])
        )

        token_network_added_events = raiden_service.default_registry.filter_token_added_events()
        token_addresses = [event['args']['token_address'] for event in token_network_added_events]

        assert token_addresses == [test_config['contracts']['token_address']]

        if test_config.get('transport') == 'udp':
            assert len(chain.address_to_discovery.keys()) == 1, repr(chain.address_to_discovery)
            assert (
                list(chain.address_to_discovery.keys())[0] ==
                to_canonical_address(test_config['contracts']['discovery_address'])
            )
            discovery = list(chain.address_to_discovery.values())[0]
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


def load_smoketest_config():
    smoketest_config_path = os.path.join(get_project_root(), 'smoketest_config.json')

    # try to load the existing smoketest genesis config
    if os.path.exists(smoketest_config_path):
        with open(smoketest_config_path) as handler:
            return json.load(handler)

    return None


def init_with_genesis(smoketest_genesis):
    with open(GENESIS_PATH, 'w') as handler:
        json.dump(smoketest_genesis, handler)

    cmd = '$RST_GETH_BINARY --datadir $RST_DATADIR init {}'.format(GENESIS_PATH)
    args = shlex.split(
        Template(cmd).substitute(os.environ),
    )
    init = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = init.communicate()
    assert init.returncode == 0
    return out, err


def start_ethereum(smoketest_genesis):
    ensure_executable(os.environ.setdefault('RST_GETH_BINARY', 'geth'))
    RST_RPC_PORT = next(get_free_port('127.0.0.1', 27854))
    os.environ['RST_RPC_PORT'] = str(RST_RPC_PORT)
    cmd = os.environ.get('RST_ETH_COMMAND', DEFAULT_ETH_COMMAND)
    args = shlex.split(
        Template(cmd).substitute(os.environ),
    )

    keystore = os.path.join(os.environ['RST_DATADIR'], 'keystore')
    if not os.path.exists(keystore):
        os.makedirs(keystore)
    with open(os.path.join(keystore, 'account.json'), 'w') as handler:
        json.dump(TEST_ACCOUNT, handler)
    with open(os.path.join(keystore, 'password'), 'w') as handler:
        handler.write(TEST_ACCOUNT_PASSWORD)

    init_out, init_err = init_with_genesis(smoketest_genesis)

    args.extend(['--password', os.path.join(keystore, 'password')])
    ethereum_node = subprocess.Popen(
        args,
        universal_newlines=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding='UTF-8',
    )
    ethereum_node.stdin.write(TEST_ACCOUNT_PASSWORD + os.linesep)
    time.sleep(.1)
    ethereum_node.stdin.write(TEST_ACCOUNT_PASSWORD + os.linesep)
    ethereum_config = dict(
        rpc=os.environ['RST_RPC_PORT'],
        keystore=keystore,
        address=to_checksum_address(TEST_ACCOUNT['address']),
        init_log_out=init_out,
        init_log_err=init_err,
    )
    return ethereum_node, ethereum_config


def deploy_smoketest_contracts(client, chain_id):
    client.web3.personal.unlockAccount(
        client.web3.eth.accounts[0],
        TEST_ACCOUNT_PASSWORD,
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


def get_private_key():
    keystore = os.path.join(os.environ['RST_DATADIR'], 'keystore')
    accmgr = AccountManager(keystore)
    if not accmgr.accounts:
        raise RuntimeError('No Ethereum accounts found in the user\'s system')

    addresses = list(accmgr.accounts.keys())
    return accmgr.get_privkey(addresses[0], TEST_ACCOUNT_PASSWORD)


def setup_testchain_and_raiden(smoketest_config, transport, matrix_server, print_step):
    print_step('Starting Ethereum node')
    ethereum, ethereum_config = start_ethereum(smoketest_config['genesis'])
    port = ethereum_config['rpc']
    web3_client = Web3(HTTPProvider(f'http://0.0.0.0:{port}'))
    web3_client.middleware_stack.inject(geth_poa_middleware, layer=0)
    random_marker = hexlify(b'raiden').decode()
    privatekeys = []
    geth_wait_and_check(web3_client, privatekeys, random_marker)

    print_step('Deploying Raiden contracts')

    client = JSONRPCClient(web3_client, get_private_key())
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
    password_file = os.path.join(args['keystore_path'], 'password')
    with open(password_file, 'w') as handler:
        handler.write('password')

    args['password_file'] = click.File()(password_file)
    args['datadir'] = args['keystore_path']
    return dict(
        args=args,
        contract_addresses=contract_addresses,
        ethereum=ethereum,
        ethereum_config=ethereum_config,
        token=token,
    )
