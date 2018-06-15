#!/usr/bin/env python
import json

import click

from create_compilation_dump import deploy_all
from genesis_builder import generate_accounts, mk_genesis
from raiden.accounts import Account
from raiden.utils import safe_address_decode
from startcluster import create_node_configuration, to_cmd
from startcluster import RAIDEN_PORT as START_PORT


def build_node_list(hosts, nodes_per_host):
    node_list = []
    for host in hosts:
        for i in range(nodes_per_host):
            node_list.append('{}:{}'.format(host, START_PORT + i))
    return node_list


@click.group()
@click.option(
    '--pretty/--no-pretty',
    default=False,
)
@click.pass_context
def cli(ctx, pretty):
    ctx.obj['pretty'] = pretty


@click.argument(
    'hosts',
    nargs=-1,
    type=str,
)
@click.argument(
    'nodes_per_host',
    default=1,
    type=int,
)
@cli.command()
@click.pass_context
def nodes(ctx, hosts, nodes_per_host):
    pretty = ctx.obj['pretty']
    if hosts is None:
        hosts = ['127.0.0.1']
    node_list = build_node_list(hosts, nodes_per_host)
    print(json.dumps(node_list, indent=2 if pretty else None))


@click.argument(
    'hosts',
    nargs=-1,
    type=str,
)
@click.argument(
    'nodes_per_host',
    default=1,
    type=int,
)
@cli.command()
@click.pass_context
def genesis(ctx, hosts, nodes_per_host):
    pretty = ctx.obj['pretty']
    node_list = build_node_list(hosts, nodes_per_host)

    accounts = generate_accounts(node_list)  # pylint: disable=redefined-outer-name
    all_addresses = [account['address'] for account in accounts.values()]

    genesis = mk_genesis(all_addresses)  # pylint: disable=redefined-outer-name

    print(json.dumps(genesis, indent=2 if pretty else None))


@click.argument(
    'hosts',
    nargs=-1,
    type=str,
)
@click.argument(
    'nodes_per_host',
    default=1,
    type=int,
)
@cli.command()
@click.pass_context
def accounts(ctx, hosts, nodes_per_host):
    pretty = ctx.obj['pretty']
    node_list = build_node_list(hosts, nodes_per_host)
    print(json.dumps(generate_accounts(node_list), indent=2 if pretty else None))


@click.argument(
    'password',
    type=str,
)
@click.argument(
    'privatekey',
    type=str,
)
@cli.command()
@click.pass_context
def private_to_account(ctx, privatekey, password):
    # privatekey is provided in the console, so it's expected to be hexadecimal
    privatekey = safe_address_decode(privatekey)

    # cast the values to bytes because it is the expected type in the Crypto library
    password = bytes(password)
    privkey = bytes(privatekey)

    account = Account.new(password, key=privkey)
    print(account.dump())


@click.argument(
    'hosts',
    nargs=-1,
    type=str,
)
@click.argument(
    'nodes_per_host',
    default=1,
    type=int,
)
@click.argument(
    'nodes_per_transfer',
    default=2,
    type=int,
)
@cli.command()
@click.pass_context
def build_scenario(ctx, hosts, nodes_per_host, nodes_per_transfer):
    # pylint: disable=too-many-locals

    pretty = ctx.obj['pretty']
    node_list = build_node_list(hosts, nodes_per_host)
    accounts = generate_accounts(node_list)  # pylint: disable=redefined-outer-name

    if nodes_per_transfer < 2:
        nodes_per_transfer = 2

    addresses = []
    for _node, data in sorted(accounts.items()):
        for k, v in data.items():
            if k == 'address':
                addresses.append(v)

    scenario = dict()
    scenario['tokens'] = tokens = list()

    # NOTE: this builds a simple ring scenario connecting the nodes
    #       in groups of `node_per_transfer`. The setup assumes
    #       unidirectional transfer from the first node to the last.
    total_tokens = len(addresses) // nodes_per_transfer
    index = 0
    for token_num in range(total_tokens):
        data_for_token = {
            "name": str(token_num),
            "channels": addresses[index:index + nodes_per_transfer],
            "transfers_with_amount": {
                addresses[index + nodes_per_transfer - 1]: 3000,
            },
        }
        tokens.append(data_for_token)
        index += nodes_per_transfer

    print(json.dumps(scenario, indent=2 if pretty else None))


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
@click.pass_context
def geth_commands(ctx, geth_hosts, datadir):
    """This is helpful to setup a private cluster of geth nodes that won't need discovery
    (because they can use the content of `static_nodes` as `static-nodes.json`).
    """
    pretty = ctx.obj['pretty']
    nodes = []  # pylint: disable=redefined-outer-name

    for i, host in enumerate(geth_hosts):
        nodes.append(create_node_configuration(host=host, node_key_seed=i))

    for node in nodes:
        node.pop('unlock')
        node.pop('rpcport')

    config = {'{host}'.format(**node): ' '.join(to_cmd(node, datadir=datadir)) for node in nodes}
    config['static_nodes'] = [node['enode'] for node in nodes]

    indent = None
    if pretty:
        indent = 2

    print(json.dumps(
        config,
        indent=indent,
    ))


@click.argument(
    'genesis_json',
    type=click.File(),
)
@click.argument(
    'state_json',
    type=click.File(),
)
@cli.command()
@click.pass_context
def merge(ctx, genesis_json, state_json):
    pretty = ctx.obj['pretty']

    genesis = json.load(genesis_json)  # pylint: disable=redefined-outer-name
    state = json.load(state_json)
    assert 'alloc' in genesis

    accounts = [key for key in genesis['alloc']]  # pylint: disable=redefined-outer-name

    for account, data in state['accounts'].items():
        if account not in accounts:
            for key in ('nonce', 'root', 'codeHash'):
                data.pop(key, None)

            genesis['alloc'][account] = data

    print(json.dumps(genesis, indent=2 if pretty else None))


@click.argument(
    'hosts',
    nargs=-1,
    type=str,
)
@click.argument(
    'nodes_per_host',
    default=1,
    type=int,
)
@click.option(
    '--scenario',
    type=click.Path(
        writable=True,
        resolve_path=True,
    ),
    default=None,
    help="(optional) update the tokens in scenario.json with predeployed token addresses. "
         "This modifies the file in place!",
)
@cli.command()
@click.pass_context
def full_genesis(ctx, hosts, nodes_per_host, scenario):
    # pylint: disable=too-many-locals

    pretty = ctx.obj['pretty']
    node_list = build_node_list(hosts, nodes_per_host)

    accounts = generate_accounts(node_list)  # pylint: disable=redefined-outer-name

    all_addresses = [
        account['address'] for account in accounts.values()
    ]

    genesis = mk_genesis(all_addresses)  # pylint: disable=redefined-outer-name

    if scenario is not None:
        with open(scenario) as handler:
            script = json.load(handler)

        token_groups = {
            token['name']: token['channels']
            for token in script['tokens']
        }
    else:
        # create tokens for addresses x addresses
        token_groups = {
            account['address']: all_addresses
            for account in accounts.values()
        }

    dump, blockchain_config = deploy_all(token_groups=token_groups)

    for account, data in dump.items():
        if account not in genesis['alloc']:
            genesis['alloc'][account] = data

    genesis['config']['raidenFlags'] = blockchain_config['raiden_flags']
    genesis['config']['token_groups'] = blockchain_config['token_groups']

    if scenario is not None:
        for token in script['tokens']:
            token['token_address'] = blockchain_config['token_groups'][token['name']]

        with open(scenario, 'w') as handler:
            json.dump(script, handler)

    print(json.dumps(genesis, indent=2 if pretty else None))


@cli.command()
def account_file():
    account = Account.new('', key="1" * 64)
    print(account.dump())


@cli.command()
def usage():
    usage_text = """\
Example usage:
==============
config_builder.py genesis 5 127.0.0.1 127.0.0.2
-> create a genesis json with funding for 10 accounts on the two hosts (see also 'accounts').

config_builder.py nodes 5 127.0.0.1 127.0.0.2
-> create json list 10 raiden endpoint addresses on the two hosts.

config_builder.py accounts 5 127.0.0.1 127.0.0.2
-> create full account-spec {endpoint: (privatekey, address)} for 10 nodes on the two hosts.

config_builder.py geth_commands /tmp/foo 127.0.0.1 127.0.0.2
-> create commands for geth nodes on both hosts with the datadir set to /tmp/foo.

config_builder.py geth_static_nodes 127.0.0.1 127.0.0.2
-> outputs geth compatible static-nodes.json contents for a private blockchain.

config_builder.py account_file
-> create an account file that can be used as etherbase in geth instances.

config_builder.py merge state_dump.json genesis.json
-> merge the deployed contracts of state_dump.json into genesis.json and create
a new genesis.json.

config_builder.py private_to_account deadbeef...feedbead password
-> encrypt the privatekey "deadbeef...feadbead" with "password" and print json accountfile.
"""

    print(usage_text)


if __name__ == '__main__':
    cli(obj={})  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
