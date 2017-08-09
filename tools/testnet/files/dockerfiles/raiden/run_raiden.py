#!/usr/bin/env python
import os

import click
import sys


ETH_RPC_ENDPOINT_ARG = '--eth-rpc-endpoint'


@click.command()
@click.option("--eth-nodes", required=True)
@click.option("--seed", required=True)
@click.option("--raiden-executable", default="raiden", show_default=True)
@click.argument("raiden_args", nargs=-1)
def main(eth_nodes, seed, raiden_executable, raiden_args):
    if ETH_RPC_ENDPOINT_ARG in raiden_args:
        raise RuntimeError("Argument conflict: {}".format(ETH_RPC_ENDPOINT_ARG))
    eth_nodes = eth_nodes.split(",")
    offset = sum(ord(c) for c in seed) % len(eth_nodes)
    target_eth_node = eth_nodes[offset]
    raiden_args = [raiden_executable] + list(raiden_args) + [ETH_RPC_ENDPOINT_ARG, target_eth_node]
    print(" ".join(raiden_args))
    # Ensure print is flushed - exec could swallow it
    sys.stdout.flush()
    os.execvp(raiden_args[0], raiden_args)


if __name__ == "__main__":
    main()
