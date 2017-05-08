# -*- coding: utf-8 -*-
from __future__ import print_function, division

import json
import os
import shutil
import subprocess
import sys
import termios
import time

import gevent
import psutil
from devp2p.crypto import privtopub
from ethereum import slogging
from ethereum.utils import denoms, encode_hex
from pyethapp.jsonrpc import address_encoder
from pyethapp.rpc_client import JSONRPCClient
from requests import ConnectionError

from raiden.utils import privatekey_to_address
from raiden.settings import GAS_LIMIT_HEX

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

DEFAULT_BALANCE = denoms.ether * 10000000
DEFAULT_BALANCE_BIN = str(denoms.ether * 10000000)
DEFAULT_PASSPHRASE = 'notsosecret'  # Geth's account passphrase
DAGSIZE = 1073739912

GENESIS_STUB = {
    'config': {
        'homesteadBlock': 0,
    },
    'nonce': '0x0000000000000042',
    'mixhash': '0x0000000000000000000000000000000000000000000000000000000000000000',
    'difficulty': '0x1',
    'coinbase': '0x0000000000000000000000000000000000000000',
    'timestamp': '0x00',
    'parentHash': '0x0000000000000000000000000000000000000000000000000000000000000000',
    'extraData': '0x' + 'raiden'.encode('hex'),
    'gasLimit': GAS_LIMIT_HEX,
}


def wait_until_block(chain, block):
    # we expect `next_block` to block until the next block, but, it could
    # advance miss and advance two or more
    curr_block = chain.block_number()
    while curr_block < block:
        curr_block = chain.next_block()


def geth_to_cmd(node, datadir, verbosity):
    """
    Transform a node configuration into a cmd-args list for `subprocess.Popen`.

    Args:
        node (dict): a node configuration
        datadir (str): the node's datadir

    Return:
        List[str]: cmd-args list
    """
    node_config = [
        'nodekeyhex',
        'port',
        'rpcport',
        'bootnodes',
        'minerthreads',
        'unlock'
    ]

    cmd = ['geth']

    for config in node_config:
        if config in node:
            value = node[config]
            cmd.extend(['--{}'.format(config), str(value)])

    if 'minerthreads' in node:
        cmd.extend(['--mine', '--etherbase', '0'])

    # dont use the '--dev' flag
    cmd.extend([
        '--nodiscover',
        '--ipcdisable',
        '--rpc',
        '--rpcaddr', '0.0.0.0',
        '--networkid', '627',
        '--verbosity', str(verbosity),
        '--fakepow',
        '--datadir', datadir,
    ])

    log.debug('geth command: {}'.format(cmd))

    return cmd


def geth_create_account(datadir, privkey):
    """
    Create an account in `datadir` -- since we're not interested
    in the rewards, we don't care about the created address.

    Args:
        datadir (str): the datadir in which the account is created
    """
    keyfile_path = os.path.join(datadir, 'keyfile')
    with open(keyfile_path, 'w') as handler:
        handler.write(privkey.encode('hex'))

    create = subprocess.Popen(
        ['geth', '--datadir', datadir, 'account', 'import', keyfile_path],
        stdin=subprocess.PIPE,
        universal_newlines=True
    )

    create.stdin.write(DEFAULT_PASSPHRASE + os.linesep)
    time.sleep(.1)
    create.stdin.write(DEFAULT_PASSPHRASE + os.linesep)
    create.communicate()
    assert create.returncode == 0


def geth_bare_genesis(genesis_path, private_keys):
    """Creates a bare genesis inside `datadir`.

    Args:
        datadir (str): the datadir in which the blockchain is initialized.

    Returns:
        str: The path to the genisis file.
    """
    account_addresses = [
        privatekey_to_address(key)
        for key in set(private_keys)
    ]

    alloc = {
        address_encoder(address): {
            'balance': DEFAULT_BALANCE_BIN,
        }
        for address in account_addresses
    }
    genesis = GENESIS_STUB.copy()
    genesis['alloc'] = alloc

    with open(genesis_path, 'w') as handler:
        json.dump(genesis, handler)


def geth_init_datadir(datadir, genesis_path):
    """Initialize a clients datadir with our custom genesis block.

    Args:
        datadir (str): the datadir in which the blockchain is initialized.
    """
    try:
        subprocess.check_output([
            'geth',
            '--datadir',
            datadir,
            'init',
            genesis_path],
            stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        raise ValueError(
            """Initializing geth with custom genesis returned {} with error:
{}""".format(e.returncode, e.output))


def geth_wait_and_check(privatekeys, rpc_ports):
    """ Wait until the geth cluster is ready. """
    address = address_encoder(privatekey_to_address(privatekeys[0]))
    jsonrpc_running = False
    tries = 5
    rpc_port = rpc_ports[0]
    jsonrpc_client = JSONRPCClient(
        host='0.0.0.0',
        port=rpc_port,
        privkey=privatekeys[0],
        print_communication=False,
    )

    while not jsonrpc_running and tries > 0:
        try:
            jsonrpc_client.call('eth_getBalance', address, 'latest')
            jsonrpc_running = True
        except ConnectionError:
            gevent.sleep(0.5)
            tries -= 1

    if jsonrpc_running is False:
        raise ValueError('geth didnt start the jsonrpc interface')

    for key in set(privatekeys):
        address = address_encoder(privatekey_to_address(key))
        jsonrpc_client = JSONRPCClient(
            host='0.0.0.0',
            port=rpc_port,
            privkey=key,
            print_communication=False,
        )

        tries = 10
        balance = '0x0'
        while balance == '0x0' and tries > 0:
            balance = jsonrpc_client.call('eth_getBalance', address, 'latest')
            gevent.sleep(1)
            tries -= 1

        if balance == '0x0':
            raise ValueError('account is with a balance of 0')


def geth_create_blockchain(
        deploy_key,
        private_keys,
        blockchain_private_keys,
        rpc_ports,
        p2p_ports,
        base_datadir,
        verbosity,
        genesis_path=None,
        logdirectory=None):
    # pylint: disable=too-many-locals,too-many-statements,too-many-arguments

    # the smallest DAG, the one for the first epoch should be a bit over 1GB,
    # since the DAG is used during proof of work and the file is mmaped from
    # disk, there must be more than 1GB of memory freely available to avoid
    # memory paging, otherwise the proof-of-work will be extremely slow
    # increasing the flakiness of the tests.
    memory = psutil.virtual_memory()
    if memory.available < DAGSIZE * 1.5:
        raise RuntimeError(
            'To properly run the tests with a geth miner '
            'at least 1.5 GB of available memory is required.'
        )

    nodes_configuration = []
    key_p2p_rpc = zip(blockchain_private_keys, p2p_ports, rpc_ports)

    for pos, (key, p2p_port, rpc_port) in enumerate(key_p2p_rpc):
        config = dict()

        # make the first node miner
        if pos == 0:
            config['minerthreads'] = 1  # conservative
            config['unlock'] = 0

        config['nodekey'] = key
        config['nodekeyhex'] = encode_hex(key)
        config['pub'] = encode_hex(privtopub(key))
        config['address'] = privatekey_to_address(key)
        config['port'] = p2p_port
        config['rpcport'] = rpc_port
        config['enode'] = 'enode://{pub}@127.0.0.1:{port}'.format(
            pub=config['pub'],
            port=config['port'],
        )
        nodes_configuration.append(config)

    for config in nodes_configuration:
        config['bootnodes'] = ','.join(node['enode'] for node in nodes_configuration)

    all_keys = list(private_keys)
    all_keys.append(deploy_key)  # needs to be at the end because of the minerthreads keys

    cmds = []
    for i, config in enumerate(nodes_configuration):
        # HACK: Use only the first 8 characters to avoid golang's issue
        # https://github.com/golang/go/issues/6895 (IPC bind fails with path
        # longer than 108 characters).
        nodekey_part = config['nodekeyhex'][:8]
        nodedir = os.path.join(base_datadir, nodekey_part)
        node_genesis_path = os.path.join(nodedir, 'custom_genesis.json')

        assert len(nodedir + '/geth.ipc') < 108, 'geth data path is too large'

        os.makedirs(nodedir)

        if genesis_path is None:
            geth_bare_genesis(node_genesis_path, all_keys)
        else:
            shutil.copy(genesis_path, node_genesis_path)

        geth_init_datadir(nodedir, node_genesis_path)

        if 'minerthreads' in config:
            geth_create_account(nodedir, private_keys[i])

        commandline = geth_to_cmd(config, nodedir, verbosity)
        cmds.append(commandline)

    # save current term settings before running geth
    if isinstance(sys.stdin, file):  # check that the test is running on non-capture mode
        term_settings = termios.tcgetattr(sys.stdin)

    stdout = None
    stderr = None
    processes_list = []
    for pos, cmd in enumerate(cmds):
        if logdirectory:
            log_path = os.path.join(logdirectory, str(pos))
            logfile = open(log_path, 'w')

            stdout = logfile
            stderr = logfile

        if '--unlock' in cmd:
            process = subprocess.Popen(
                cmd,
                universal_newlines=True,
                stdin=subprocess.PIPE,
                stdout=stdout,
                stderr=stderr,
            )

            # --password wont work, write password to unlock
            process.stdin.write(DEFAULT_PASSPHRASE + os.linesep)  # Passphrase:
            process.stdin.write(DEFAULT_PASSPHRASE + os.linesep)  # Repeat passphrase:
        else:
            process = subprocess.Popen(
                cmd,
                universal_newlines=True,
                stdout=stdout,
                stderr=stderr,
            )

        processes_list.append(process)
        assert process.returncode is None

    geth_wait_and_check(private_keys, rpc_ports)

    # reenter echo mode (disabled by geth pasphrase prompt)
    if isinstance(sys.stdin, file):
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, term_settings)

    return processes_list
