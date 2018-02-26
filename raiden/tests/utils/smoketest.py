# -*- coding: utf-8 -*-
from binascii import hexlify, unhexlify
import os
import time
import json
import subprocess
import shlex
import tempfile
import distutils.spawn
import pdb
import traceback
import requests
from http import HTTPStatus
from string import Template

from ethereum.tools._solidity import get_solidity

from raiden.tests.utils.tester_client import (
    tester_deploy_contract,
    BlockChainServiceTesterMock,
    NettingChannelTesterMock,
)
from raiden.utils import (
    get_contract_path,
    get_project_root,
    fix_tester_storage,
    address_encoder,
    address_decoder,
)
from raiden.blockchain.abi import contract_checksum
from raiden.transfer.state import CHANNEL_STATE_OPENED
from raiden.tests.utils.genesis import GENESIS_STUB
from raiden.tests.utils.tester import create_tester_chain
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
RST_GETH_BINARY = distutils.spawn.find_executable('geth')
if RST_GETH_BINARY is not None and 'RST_GETH_BINARY' not in os.environ:
    os.environ['RST_GETH_BINARY'] = RST_GETH_BINARY


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
        'version': 1
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
            address_decoder(test_config['contracts']['registry_address'])
        )
        assert (
            raiden_service.default_registry.token_addresses() ==
            [address_decoder(test_config['contracts']['token_address'])]
        )
        assert len(chain.address_to_discovery.keys()) == 1
        assert (
            list(chain.address_to_discovery.keys())[0] ==
            address_decoder(test_config['contracts']['discovery_address'])
        )
        discovery = list(chain.address_to_discovery.values())[0]
        assert discovery.endpoint_by_address(raiden_service.address) != TEST_ENDPOINT

        assert len(raiden_service.token_to_channelgraph.values()) == 1
        graph = list(raiden_service.token_to_channelgraph.values())[0]
        channel = graph.partneraddress_to_channel[unhexlify(TEST_PARTNER_ADDRESS)]
        assert channel.can_transfer
        assert channel.contract_balance == channel.distributable == TEST_DEPOSIT_AMOUNT
        assert channel.state == CHANNEL_STATE_OPENED
        run_restapi_smoketests(raiden_service, test_config)
    except Exception:
        error = traceback.format_exc()
        if debug:
            pdb.post_mortem()
        return error


def load_or_create_smoketest_config():
    # get the contract and compiler (if available) versions
    versions = dict()
    for file in os.listdir(get_contract_path('')):
        if file.endswith('.sol'):
            versions[file] = contract_checksum(get_contract_path(file))
    # if solc is available, record its version, too
    if get_solidity() is not None:
        solc_version_out, _ = subprocess.Popen(
            [get_solidity().compiler_available(), '--version'],
            stdout=subprocess.PIPE
        ).communicate()
        versions['solc'] = solc_version_out.split()[-1].decode()

    smoketest_config_path = os.path.join(
        get_project_root(),
        'smoketest_config.json'
    )
    # try to load an existing smoketest genesis config
    smoketest_config = dict()
    if os.path.exists(smoketest_config_path):
        with open(smoketest_config_path) as handler:
            smoketest_config = json.load(handler)
        # if the file versions still fit, return the genesis config (ignore solc if not available)
        config_matches = [
            versions[key] == smoketest_config['versions'][key]
            for key in versions.keys()
        ]
        if all(config_matches):
            return smoketest_config

    # something did not fit -- we will create the genesis
    smoketest_config['versions'] = versions
    raiden_config, smoketest_genesis = complete_genesis()
    smoketest_config['genesis'] = smoketest_genesis
    smoketest_config.update(raiden_config)
    with open(os.path.join(get_project_root(), 'smoketest_config.json'), 'w') as handler:
        json.dump(smoketest_config, handler)
    return smoketest_config


def deploy_and_open_channel_alloc(deployment_key):
    """ Compiles, deploys and dumps a minimal raiden smart contract environment for use in a
    genesis block. This will:
        - deploy the raiden Registry contract stack
        - deploy a token contract
        - open a channel for the TEST_ACCOUNT address
        - deploy the EndpointRegistry/discovery contract
        - register a known value for the TEST_ACCOUNT address
        - dump the complete state in a genesis['alloc'] compatible format
        - return the state dump and the contract addresses
    """
    deployment_key_bin = unhexlify(deployment_key)
    state = create_tester_chain(
        deployment_key_bin,
        [deployment_key_bin],
        6 * 10 ** 6
    )

    registry_address = tester_deploy_contract(
        state,
        deployment_key_bin,
        'Registry',
        get_contract_path('Registry.sol'),
    )

    discovery_address = tester_deploy_contract(
        state,
        deployment_key_bin,
        'EndpointRegistry',
        get_contract_path('EndpointRegistry.sol'),
    )

    client = BlockChainServiceTesterMock(
        deployment_key_bin,
        state,
    )

    registry = client.registry(registry_address)

    token_address = client.deploy_and_register_token(
        registry,
        'HumanStandardToken',
        get_contract_path('HumanStandardToken.sol'),
        constructor_parameters=(100, 'smoketesttoken', 2, 'RST')
    )

    manager = registry.manager_by_token(token_address)
    assert manager.private_key == deployment_key_bin

    channel_address = manager.new_netting_channel(
        unhexlify(TEST_PARTNER_ADDRESS),
        50
    )

    client.token(token_address).approve(channel_address, TEST_DEPOSIT_AMOUNT)
    channel = NettingChannelTesterMock(
        state,
        deployment_key_bin,
        channel_address
    )
    channel.deposit(TEST_DEPOSIT_AMOUNT)

    discovery = client.discovery(discovery_address)
    discovery.proxy.registerEndpoint(TEST_ENDPOINT)

    contracts = dict(
        registry_address=address_encoder(registry_address),
        token_address=address_encoder(token_address),
        discovery_address=address_encoder(discovery_address),
        channel_address=address_encoder(channel_address),
    )

    alloc = dict()
    # preserve all accounts and contracts
    for address in state.head_state.to_dict().keys():
        alloc[address] = state.head_state.account_to_dict(address)

    for account, content in alloc.items():
        alloc[account]['storage'] = fix_tester_storage(content['storage'])

    return dict(
        alloc=alloc,
        contracts=contracts,
    )


def complete_genesis():
    smoketest_genesis = GENESIS_STUB.copy()
    smoketest_genesis['config']['clique'] = {'period': 1, 'epoch': 30000}
    smoketest_genesis['extraData'] = '0x{:0<64}{:0<170}'.format(
        hexlify(b'raiden').decode(),
        TEST_ACCOUNT['address'],
    )
    smoketest_genesis['alloc'][TEST_ACCOUNT['address']] = dict(balance=hex(10 ** 18))

    raiden_config = deploy_and_open_channel_alloc(deployment_key=TEST_PRIVKEY)
    smoketest_genesis['alloc'].update(
        raiden_config['alloc']
    )
    return raiden_config, smoketest_genesis


def init_with_genesis(smoketest_genesis):
    with open(GENESIS_PATH, 'w') as handler:
        json.dump(smoketest_genesis, handler)

    cmd = '$RST_GETH_BINARY --datadir $RST_DATADIR init {}'.format(GENESIS_PATH)
    args = shlex.split(
        Template(cmd).substitute(os.environ)
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
    RST_RPC_PORT = next(get_free_port('127.0.0.1', 27854))
    os.environ['RST_RPC_PORT'] = str(RST_RPC_PORT)
    cmd = os.environ.get('RST_ETH_COMMAND', DEFAULT_ETH_COMMAND)
    args = shlex.split(
        Template(cmd).substitute(os.environ)
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
        address=TEST_ACCOUNT['address'],
        init_log_out=init_out,
        init_log_err=init_err,
    )
    return ethereum_node, ethereum_config
