#!/usr/bin/env python
import click
from web3 import HTTPProvider, Web3

from raiden.network.rpc.client import JSONRPCClient

WEI_TO_ETH = 10 ** 18


@click.command()
@click.argument("private-key")
@click.argument("eth-amount", type=int)
@click.argument("targets_file", type=click.File())
@click.option("-p", "--port", default=8545)
@click.option("-h", "--host", default="127.0.0.1")
def main(private_key, eth_amount, targets_file, port, host):
    web3 = Web3(HTTPProvider(f'http://{host}:{port}'))
    client = JSONRPCClient(web3, private_key)

    targets = [t.strip() for t in targets_file]
    balance = client.balance(client.sender)

    balance_needed = len(targets) * eth_amount
    if balance_needed * WEI_TO_ETH > balance:
        print("Not enough balance to fund {} accounts with {} eth each. Need {}, have {}".format(
            len(targets),
            eth_amount,
            balance_needed,
            balance / WEI_TO_ETH,
        ))

    print("Sending {} eth to:".format(eth_amount))
    for target in targets:
        print("  - {}".format(target))
        client.send_transaction(to=target, value=eth_amount * WEI_TO_ETH)


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
