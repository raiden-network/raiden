# -*- coding: utf-8 -*-
from binascii import hexlify
from binascii import unhexlify
from http import HTTPStatus
from string import Template
import json
import os
import sys
import pdb
import requests
import shlex
import shutil
import subprocess
import tempfile
import time
import traceback

from eth_utils import to_checksum_address, to_canonical_address

from raiden.utils import get_project_root
from raiden.transfer import channel, views
from raiden.transfer.state import CHANNEL_STATE_OPENED
from raiden.network.utils import get_free_port
from raiden.connection_manager import ConnectionManager

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
    --rpcapi eth,net,web3
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


def run_restapi_smoketests(raiden_service, test_config):
    """Test if REST api works. """
    url = 'http://localhost:{port}/api/1/channels'.format(port=5001)

    response = requests.get(url)

    assert response.status_code == HTTPStatus.OK

    response_json = response.json()
    assert (response_json[0]['partner_address'] ==
            '0x' + hexlify(ConnectionManager.BOOTSTRAP_ADDR).decode())
    assert response_json[0]['state'] == 'opened'
    assert response_json[0]['balance'] > 0


def run_smoketests(raiden_service, test_config, debug=False):
    """ Test that the assembled raiden_service correctly reflects the configuration from the
    smoketest_genesis. """
    try:
        chain = raiden_service.chain
        assert (
            raiden_service.default_registry.address ==
            to_canonical_address(test_config['contracts']['registry_address'])
        )
        assert (
            raiden_service.default_registry.token_addresses() ==
            [to_canonical_address(test_config['contracts']['token_address'])]
        )
        assert len(chain.address_to_discovery.keys()) == 1
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
        run_restapi_smoketests(raiden_service, test_config)
    except Exception:
        error = traceback.format_exc()
        if debug:
            pdb.post_mortem()
        return error


def load_smoketest_config():
    smoketest_config_path = os.path.join(get_project_root(), 'smoketest_config.json')

    # try to load the existing smoketest genesis config
    smoketest_config = dict()
    if os.path.exists(smoketest_config_path):
        with open(smoketest_config_path) as handler:
            smoketest_config = json.load(handler)
            return smoketest_config

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
