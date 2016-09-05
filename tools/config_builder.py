#!/usr/bin/env python

import click
import json
from genesis_builder import generate_accounts, mk_genesis
from create_compilation_dump import deploy_all
from startcluster import RAIDEN_PORT as START_PORT
from startcluster import create_node_configuration, update_bootnodes, to_cmd
from pyethapp.accounts import Account


def build_node_list(hosts, nodes_per_host):
    node_list = []
    for host in hosts:
        for i in range(nodes_per_host):
            node_list.append('{}:{}'.format(host, START_PORT + i))
    return node_list


@click.group()
def cli():
    pass


@click.argument(
    'hosts',
    nargs=-1,
    type=str,
)
@click.argument(
    'nodes_per_host',
    default=1,
    type=int
)
@cli.command()
def nodes(hosts, nodes_per_host):
    if hosts is None:
        hosts = ['127.0.0.1']
    node_list = build_node_list(hosts, nodes_per_host)
    print json.dumps(node_list, indent=2)


@click.argument(
    'hosts',
    nargs=-1,
    type=str,
)
@click.argument(
    'nodes_per_host',
    default=1,
    type=int
)
@cli.command()
def genesis(hosts, nodes_per_host):
    node_list = build_node_list(hosts, nodes_per_host)
    accounts = generate_accounts(node_list)
    genesis = mk_genesis([acc['address'] for acc in accounts.values()])
    print json.dumps(genesis, indent=2)


@click.argument(
    'hosts',
    nargs=-1,
    type=str,
)
@click.argument(
    'nodes_per_host',
    default=1,
    type=int
)
@cli.command()
def accounts(hosts, nodes_per_host):
    node_list = build_node_list(hosts, nodes_per_host)
    print json.dumps(generate_accounts(node_list), indent=2)


@click.argument(
    'geth_hosts',
    nargs=-1,
    type=str,
)
@click.argument(
    'datadir',
    type=str,
)
@cli.command()
def geth_commands(geth_hosts, datadir):
    """This is helpful to setup a private cluster of geth nodes that won't need discovery
    (because they will have their `bootnodes` parameter pointed at each other).
    """
    nodes = []
    for i, host in enumerate(geth_hosts):
        nodes.append(create_node_configuration(host=host, node_key_seed=i))
    for node in nodes:
        node.pop('unlock')
        node.pop('rpcport')
    update_bootnodes(nodes)
    print json.dumps(
        {'{host}:{port}'.format(**node): ' '.join(to_cmd(node, datadir=datadir)) for node in nodes},
        indent=2)


@click.argument(
    'genesis_json',
    type=click.File()
)
@click.argument(
    'state_json',
    type=click.File()
)
@cli.command()
def merge(genesis_json, state_json):
    genesis = json.load(genesis_json)
    state = json.load(state_json)
    assert 'alloc' in genesis
    accounts = [key for key in genesis['alloc']]
    for account, data in state['accounts'].items():
        if account not in accounts:
            [data.pop(key) for key in "nonce root codeHash".split()]
            genesis['alloc'][account] = data
    print json.dumps(genesis, indent=2)


@click.argument(
    'hosts',
    nargs=-1,
    type=str,
)
@click.argument(
    'nodes_per_host',
    default=1,
    type=int
)
@cli.command()
def full_genesis(hosts, nodes_per_host):
    node_list = build_node_list(hosts, nodes_per_host)
    accounts = generate_accounts(node_list)
    genesis = mk_genesis([acc['address'] for acc in accounts.values()])
    dump, blockchain_config = deploy_all()
    for account, data in dump.items():
        if not account in genesis['alloc']:
            genesis['alloc'][account] = data
    genesis['config']['raidenFlags'] = blockchain_config['raiden_flags']
    print json.dumps(genesis, indent=2)


@cli.command()
def account_file():
    account = Account.new('', key="1" * 64)
    print account.dump()


@cli.command()
def usage():
    print "Example usage:"
    print "==============\n"
    print "\tconfig_builder.py genesis 5 127.0.0.1 127.0.0.2"
    print "\t-> create a genesis json with funding for 10 accounts on the two hosts (see also 'accounts')."
    print "\n"
    print "\tconfig_builder.py nodes 5 127.0.0.1 127.0.0.2"
    print "\t-> create json list 10 raiden endpoint addresses on the two hosts."
    print "\n"
    print "\tconfig_builder.py accounts 5 127.0.0.1 127.0.0.2"
    print "\t-> create full account-spec {endpoint: (privatekey, address)} for 10 nodes on the two hosts."
    print "\n"
    print "\tconfig_builder.py geth_commands /tmp/foo 127.0.0.1 127.0.0.2"
    print "\t-> create commands for geth nodes on both hosts with the datadir set to /tmp/foo."
    print "\n"
    print "\tconfig_builder.py account_file"
    print "\t-> create an account file that can be used as etherbase in geth instances."
    print "\n"
    print "\tconfig_builder.py merge state_dump.json genesis.json"
    print "\t-> merge the deployed contracts of state_dump.json into genesis.json and create a new genesis.json."

if __name__ == '__main__':
    cli()
