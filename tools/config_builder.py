#!/usr/bin/env python

import click
import json
import random
from genesis_builder import generate_accounts, mk_genesis
from create_compilation_dump import deploy_all
from startcluster import RAIDEN_PORT as START_PORT
from startcluster import create_node_configuration, to_cmd
from pyethapp.accounts import Account


def build_node_list(hosts, nodes_per_host):
    node_list = []
    for host in hosts:
        for i in range(nodes_per_host):
            node_list.append('{}:{}'.format(host, START_PORT + i))
    return node_list


@click.group()
@click.option(
    '--pretty/--no-pretty',
    default=False
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
    type=int
)
@cli.command()
@click.pass_context
def nodes(ctx, hosts, nodes_per_host):
    pretty = ctx.obj['pretty']
    if hosts is None:
        hosts = ['127.0.0.1']
    node_list = build_node_list(hosts, nodes_per_host)
    print json.dumps(node_list, indent=2 if pretty else None)


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
@click.pass_context
def genesis(ctx, hosts, nodes_per_host):
    pretty = ctx.obj['pretty']
    node_list = build_node_list(hosts, nodes_per_host)
    accounts = generate_accounts(node_list)
    genesis = mk_genesis([acc['address'] for acc in accounts.values()])
    print json.dumps(genesis, indent=2 if pretty else None)


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
@click.pass_context
def accounts(ctx, hosts, nodes_per_host):
    pretty = ctx.obj['pretty']
    node_list = build_node_list(hosts, nodes_per_host)
    print json.dumps(generate_accounts(node_list), indent=2 if pretty else None)


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
@click.pass_context
def build_scenario(ctx, hosts, nodes_per_host):
    pretty = ctx.obj['pretty']
    node_list = build_node_list(hosts, nodes_per_host)
    accounts = generate_accounts(node_list)

    addresses = []
    for node, data in accounts.items():
        for k, v in data.items():
            if k == 'address':
                addresses.append(v)

    random.shuffle(addresses)

    scenario = dict()
    scenario['assets'] = assets = list()

    # TODO: this builds a simple test scenario connecting each
    #       node to some other node one-by-one (for odd number,
    #       ignores last one)...
    total_assets = len(addresses) // 2
    index = 0
    for asset_num in range(total_assets):
        data_for_asset = {
            "name": str(asset_num),
            "channels": [addresses[index], addresses[index + 1]],
            "transfers_with_amount": {
                addresses[index]: 100,
                addresses[index + 1]: 100,
            }
        }
        assets.append(data_for_asset)
        index += 2

    print json.dumps(scenario, indent=2 if pretty else None)


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
    nodes = []
    for i, host in enumerate(geth_hosts):
        nodes.append(create_node_configuration(host=host, node_key_seed=i))
    for node in nodes:
        node.pop('unlock')
        node.pop('rpcport')
    config = {'{host}'.format(**node): ' '.join(to_cmd(node, datadir=datadir)) for node in nodes}
    config['static_nodes'] = [node['enode'] for node in nodes]
    print json.dumps(config,
        indent=2 if pretty else None)


@click.argument(
    'genesis_json',
    type=click.File()
)
@click.argument(
    'state_json',
    type=click.File()
)
@cli.command()
@click.pass_context
def merge(ctx, genesis_json, state_json):
    pretty = ctx.obj['pretty']
    genesis = json.load(genesis_json)
    state = json.load(state_json)
    assert 'alloc' in genesis
    accounts = [key for key in genesis['alloc']]
    for account, data in state['accounts'].items():
        if account not in accounts:
            [data.pop(key) for key in "nonce root codeHash".split()]
            genesis['alloc'][account] = data
    print json.dumps(genesis, indent=2 if pretty else None)


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
@click.option(
    '--scenario',
    type=click.Path(
        writable=True,
        resolve_path=True,
    ),
    default=None,
    help="(optional) update the assets in scenario.json with predeployed token addresses. "
         "This modifies the file in place!"
)
@cli.command()
@click.pass_context
def full_genesis(ctx, hosts, nodes_per_host, scenario):
    pretty = ctx.obj['pretty']
    node_list = build_node_list(hosts, nodes_per_host)
    accounts = generate_accounts(node_list)
    genesis = mk_genesis([acc['address'] for acc in accounts.values()])

    if scenario is not None:
        with open(scenario) as f:
            script = json.load(f)
        token_groups = {asset['name']: asset['channels']
                        for asset in script['assets']
                        }
    else:
        # create tokens for addresses x addresses
        token_groups = {
        account['address']: [acc['address'] for acc in accounts.values()]
        for account in accounts.values()
    }

    dump, blockchain_config = deploy_all(token_groups=token_groups)

    for account, data in dump.items():
        if not account in genesis['alloc']:
            genesis['alloc'][account] = data

    genesis['config']['raidenFlags'] = blockchain_config['raiden_flags']
    genesis['config']['token_groups'] = blockchain_config['token_groups']

    if scenario is not None:
        for asset in script['assets']:
            asset['token_address'] = blockchain_config['token_groups'][asset['name']]
        with open(scenario, 'w') as f:
            json.dump(script, f)

    print json.dumps(genesis, indent=2 if pretty else None)


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
    print "\tconfig_builder.py geth_static_nodes 127.0.0.1 127.0.0.2"
    print "\t-> outputs geth compatible static-nodes.json contents for a private blockchain."
    print "\n"
    print "\tconfig_builder.py account_file"
    print "\t-> create an account file that can be used as etherbase in geth instances."
    print "\n"
    print "\tconfig_builder.py merge state_dump.json genesis.json"
    print "\t-> merge the deployed contracts of state_dump.json into genesis.json and create a new genesis.json."

if __name__ == '__main__':
    cli(obj={})
