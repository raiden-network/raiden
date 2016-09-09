#!/usr/bin/env python
import os
import shlex
import json
import time
import tempfile
import signal
from subprocess import Popen, PIPE

from raiden.utils import privatekey_to_address
from ethereum.utils import sha3, encode_hex
from devp2p.crypto import privtopub as privtopub_enode

from genesis_builder import mk_genesis, generate_accounts

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

# a list of `num_raiden_accounts` account addresses with a predictable privkey:
# privkey = sha3('127.0.0.1:`raiden_port + i`')
DEFAULTACCOUNTS = [
    value['address']
    for value in generate_accounts([
        '127.0.0.1:{}'.format(RAIDEN_PORT + i)
        for i in range(NUM_RAIDEN_ACCOUNTS)
    ]).values()
]


def prepare_for_exec(nodes, parentdir, accounts=DEFAULTACCOUNTS):
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
        init_datadir(nodedir, accounts=accounts)
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
        assert isinstance(datadir, basestring)
        cmd.append('--datadir {}'.format(datadir))
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


def create_node_configurations(num_nodes,
                               miner=True,
                               start_port=30301,
                               start_rpcport=8101,
                               host='127.0.0.1',
                               ):
    """
    Create multiple configurations (ports, keys, etc...) for `num_nodes` on `host`.

    :param num_nodes: the number of nodes to create
    :param miner: if True, setup the first node to be a mining node
    :param start_port: the first p2p port to assign
    :param start_rpcport: the first rpc port to assign
    :return: list of node configurations (dicts)
    """
    nodes = []
    for i in range(num_nodes):
        node = create_node_configuration(
            miner=miner and i == 0,
            port=start_port + i,
            rpcport=start_rpcport + i,
            node_key_seed=i
        )
        nodes.append(node)
    return nodes


def create_node_configuration(miner=True,
                              port=30301,
                              rpcport=8101,
                              host='127.0.0.1',
                              node_key_seed=0):
    """
    Create configuration (ports, keys, etc...) for one node.

    :param miner: if True, setup to be a mining node
    :param port: the p2p port to assign
    :param rpcport: the port to assign
    :param host: the host for the node to run on
    :return: node configuration dict
    """
    node = dict()
    if miner:
        node['minerthreads'] = 1  # conservative
        node['unlock'] = 0
    node['nodekey'] = sha3('node:{}'.format(node_key_seed))
    node['nodekeyhex'] = encode_hex(node['nodekey'])
    node['pub'] = encode_hex(privtopub_enode(node['nodekey']))
    node['address'] = privatekey_to_address(node['nodekey'])
    node['host'] = host
    node['port'] = port
    node['rpcport'] = rpcport
    node['enode'] = 'enode://{pub}@{host}:{port}'.format(**node)
    return node


def update_bootnodes(nodes):
    """Join the bootnodes for number of node configurations.
    """
    for node in nodes:
        node['bootnodes'] = ','.join(node['enode'] for node in nodes)


def boot(cmds):
    """
    Run all `cmds` with a shutdown handler attached.
    """
    processes = []
    try:
        for cmd in cmds:
            if '--unlock' in cmd:
                proc = Popen(
                    cmd,
                    universal_newlines=True,
                    stdin=PIPE,
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
    update_bootnodes(nodes)
    cmds = prepare_for_exec(nodes, datadir)
    boot(cmds)
    while True:
        time.sleep(1)
