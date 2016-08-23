#!/usr/bin/env python
import os
import shlex
import json
import time
import tempfile
import signal
from subprocess import Popen, PIPE
from ethereum.utils import denoms, sha3, privtoaddr, encode_hex
from devp2p.crypto import privtopub as privtopub_enode

# DEFAULTS
NUM_GETH_NODES = 3
NUM_RAIDEN_ACCOUNTS = 10
CLUSTER_NAME = 'raiden'
RAIDEN_PORT = 40001
DEFAULT_PW = 'notsosecret'


# default args to pass to `geth` for all calls, e.g. verbosity, ...
DEFAULT_ARGS = [
    '--nodiscover',
    '--rpc',
    '--networkid {}'.format(sum(ord(c) for c in CLUSTER_NAME)),
]

# the node specific arguments to pass to `geth` that will be extracted from a
# 'node configuration'
NODE_CONFIG = [
    'nodekeyhex',
    'port',
    'rpcport',
    'bootnodes',
    'minerthreads',
    'unlock'
]

GENESIS_STUB = {
    'config': {
        'homesteadBlock': 1
    },
    'nonce': '0x0000000000000042',
    'mixhash': '0x0000000000000000000000000000000000000000000000000000000000000000',
    'difficulty': '0x4000',
    'coinbase': '0x0000000000000000000000000000000000000000',
    'timestamp': '0x00',
    'parentHash': '0x0000000000000000000000000000000000000000000000000000000000000000',
    'extraData': CLUSTER_NAME,
    'gasLimit': '0xfffffffff'
}


def generate_accounts(seeds):
    """Create private keys and addresses for all seeds.
    """
    return {
        seed: dict(
            privatekey=encode_hex(sha3(seed)),
            address=encode_hex(privtoaddr(sha3(seed)))
        ) for seed in seeds}


# a list of `num_raiden_accounts` account addresses with a predictable privkey:
# privkey = sha3('127.0.0.1:`raiden_port + i`')
DEFAULTACCOUNTS = [
    value['address'] for value in generate_accounts([
        '127.0.0.1:{}'.format(RAIDEN_PORT + i) for i in range(NUM_RAIDEN_ACCOUNTS)]).values()
]


def mk_genesis(accounts, initial_alloc=denoms.ether * 100000000):
    """
    Create a genesis-block dict with allocation for all `accounts`.

    :param accounts: list of account addresses (hex)
    :param initial_alloc: the amount to allocate for the `accounts`
    :return: genesis dict
    """
    genesis = GENESIS_STUB.copy()
    genesis['alloc'] = {
        account: {
            'balance': str(initial_alloc)
        }
        for account in accounts
    }
    return genesis


def prepare_for_exec(nodes, parentdir):
    """
    Prepare the configurations from `nodes` for execution, i.e.
    - prepare dataddirs
    - create genesis-files
    - create accounts (if necessary)
    - transform node configuration to `geth ...` cmd args

    :param nodes: list of node configurations
    :param parentdir: the datadir parent for all nodes
    :return: list of cmds for `Popen`
    """
    cmds = []
    for node in nodes:
        nodedir = os.path.join(parentdir, node['nodekeyhex'])
        os.makedirs(nodedir)
        init_datadir(nodedir)
        if 'minerthreads' in node:
            create_keystore_account(nodedir)
        cmds.append(to_cmd(node, datadir=nodedir))
    return cmds


def to_cmd(node, datadir=None):
    """
    Transform a node configuration into a cmd-args list for `subprocess.Popen`.

    :param node: a node configuration
    :param datadir: the node's datadir
    :return: cmd-args list
    """
    cmd = ['geth']
    cmd.extend(
        ['--{} {}'.format(k, v) for k, v in node.items() if k in NODE_CONFIG])
    cmd.extend(DEFAULT_ARGS)
    if 'minerthreads' in node:
        cmd.append('--mine')
        cmd.append('--etherbase 0')
    if datadir:
        assert isinstance(datadir, str)
        cmd.append('--datadir {}'.format(datadir))
    cmd.extend(DEFAULT_ARGS)
    return shlex.split(' '.join(cmd))


def create_keystore_account(datadir, privkey=encode_hex(sha3('localhost:627'))):
    """
    Create an account in `datadir` -- since we're not interested
    in the rewards, we don't care about the created address.

    :param datadir: the datadir in which the account is created
    :return: None
    """
    with open(os.path.join(datadir, 'keyfile'), 'w') as f:
        f.write(privkey)

    create = Popen(
        shlex.split('geth --datadir {} account import {}'.format(
            datadir, os.path.join(datadir, 'keyfile'))),
        stdin=PIPE, universal_newlines=True
    )
    create.stdin.write(DEFAULT_PW + os.linesep)
    time.sleep(.1)
    create.stdin.write(DEFAULT_PW + os.linesep)
    create.communicate()
    assert create.returncode == 0


def init_datadir(datadir, accounts=DEFAULTACCOUNTS):
    genesis_path = os.path.join(datadir, 'custom_genesis.json')
    with open(genesis_path, 'w') as f:
        json.dump(mk_genesis(accounts), f)
    Popen(shlex.split(
        'geth --datadir {} init {}'.format(datadir, genesis_path)
        ))


def create_node_configurations(num_nodes, miner=True, start_port=30301, start_rpcport=8101):
    """
    Create configurations (ports, keys, etc...) for `num_nodes`.

    :param num_nodes: the number of nodes to create
    :param miner: if True, setup the first node to be a mining node
    :param start_port: the first p2p port to assign
    :param start_rpcport: the first rpc port to assign
    :return: list of node configurations (dicts)
    """
    nodes = []
    for i in range(num_nodes):
        node = dict()
        if miner and i == 0:
            node['minerthreads'] = 1  # conservative
            node['unlock'] = 0
        node['nodekey'] = sha3('node:{}'.format(i))
        node['nodekeyhex'] = encode_hex(node['nodekey'])
        node['pub'] = encode_hex(privtopub_enode(node['nodekey']))
        node['address'] = privtoaddr(node['nodekey'])
        node['port'] = start_port + i
        node['rpcport'] = start_rpcport + i
        node['enode'] = 'enode://{pub}@127.0.0.1:{port}'.format(**node)
        nodes.append(node)
        for node in nodes:
            node['bootnodes'] = ','.join(node['enode'] for node in nodes)
    return nodes


def boot(cmds):
    """
    Run all `cmds` with a shutdown handler attached.
    """
    processes = []
    try:
        for cmd in cmds:
            if '--unlock' in cmd:
                proc = Popen(cmd,
                    universal_newlines=True, stdin=PIPE
                )
                # write password to unlock
                proc.stdin.write(DEFAULT_PW + os.linesep)
                processes.append(proc)
            else:
                processes.append(Popen(cmd))
                print('spawned process')
    except SystemExit:
        for process in processes:
            process.terminate()
        print('clean shutdown')
    finally:
        print('Goodbye')


def shutdown_handler(_signo, _stackframe):
    raise SystemExit

if __name__ == '__main__':
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    datadir = tempfile.mkdtemp()
    nodes = create_node_configurations(NUM_GETH_NODES)
    cmds = prepare_for_exec(nodes, datadir)
    boot(cmds)
    while True:
        time.sleep(1)
