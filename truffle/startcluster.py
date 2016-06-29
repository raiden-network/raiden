#!/usr/bin/env python
import os
import sys
import json
import tempfile
import signal
from subprocess import Popen
from ethereum.utils import denoms, sha3, privtopub, privtoaddr, encode_hex

# DEFAULTS
num_nodes = 3
cluster_name = 'raiden'
raiden_port = sum(ord(c) for c in cluster_name)

defaultaccounts = [
    encode_hex(privtopub(sha3('localhost:{}'.format(raiden_port + i))))
    for i in range(3)
]

node_config = [
    'nodekeyhex',
    'port',
    'rpcport',
    'bootnodes',
    'minerthreads',
]

flags = [
    '--nodiscover',
    '--rpc',
    '--networkid {}'.format(sum(ord(c) for c in cluster_name)),
]

genesis_stub = {
    'nonce': '0x0000000000000042',
    'mixhash': '0x0000000000000000000000000000000000000000000000000000000000000000',
    'difficulty': '0x4000',
    'coinbase': '0x0000000000000000000000000000000000000000',
    'timestamp': '0x00',
    'parentHash': '0x0000000000000000000000000000000000000000000000000000000000000000',
    'extraData': cluster_name,
    'gasLimit': '0xffffffff'
}


def to_cmd(node, accounts=defaultaccounts, datadir=None):
    cmd = ['geth']
    cmd.extend(
        ['--{} {}'.format(k, v) for k, v in node.items() if k in node_config])
    cmd.extend(flags)
    if 'minerthreads' in node:
        cmd.append('--mine')
        cmd.append('--etherbase 0')
    if datadir:
        assert isinstance(datadir, str)
        cmd.append('--datadir {}'.format(datadir))
        cmd.append('--genesis {}'.format(os.path.join(datadir, 'genesis.json')))
    return cmd


def mk_genesis(accounts, initial_alloc=denoms.ether * 10000):
    genesis = genesis_stub.copy()
    genesis['alloc'] = {
        account: {
            'balance': str(initial_alloc)
        }
        for account in accounts
    }
    return genesis


def shutdown_handler(_signo, _stackframe):
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    nodes = []
    for i in range(num_nodes):
        node = dict()
        if i == 0:
            node['minerthreads'] = 1  # conservative
        node['nodekey'] = sha3('node:{}'.format(i))
        node['nodekeyhex'] = encode_hex(node['nodekey'])
        node['pub'] = encode_hex(privtopub(node['nodekey']))
        node['address'] = privtoaddr(node['nodekey'])
        node['port'] = 30301 + i
        node['rpcport'] = 8101 + i
        node['enode'] = 'enode://{pub}@127.0.0.1:{port}'.format(**node)
        nodes.append(node)
        for node in nodes:
            node['bootnodes'] = ','.join(node['enode'] for node in nodes)

    datadir = tempfile.mkdtemp()
    cmds = []
    for node in nodes:
        nodedir = os.path.join(datadir, node['nodekeyhex'])
        os.makedirs(nodedir)
        with open(os.path.join(nodedir, 'genesis.json'), 'w') as f:
            json.dump(mk_genesis(defaultaccounts), f)
            cmds.append(' '.join(to_cmd(node, datadir=os.path.join(datadir, node['nodekeyhex']))).split())
    processes = []
    try:
        for cmd in cmds:
            print(' '.join(cmd))
            processes.append(Popen(cmd))
            print('spawned process')
    except SystemExit:
        for process in processes:
            process.terminate()
        print('clean shutdown')
    finally:
        print('Goodbye')
