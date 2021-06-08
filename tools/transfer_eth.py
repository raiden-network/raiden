#!/usr/bin/env python
import json

import click
from web3 import HTTPProvider, Web3

from raiden.accounts import Account
from raiden.network.rpc.client import EthTransfer, JSONRPCClient
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.utils.formatting import to_canonical_address, to_checksum_address

WEI_TO_ETH = 10 ** 18


@click.command()
@click.option("--keystore-file", required=True, type=click.Path(exists=True, dir_okay=False))
@click.password_option("--password", envvar="ACCOUNT_PASSWORD", confirmation_prompt=False)
@click.option("--rpc-url", default="http://localhost:8545")
@click.argument("eth-amount", type=int)
@click.argument("targets_file", type=click.File())
def main(keystore_file, password, rpc_url, eth_amount, targets_file) -> None:
    web3 = Web3(HTTPProvider(rpc_url))
    with open(keystore_file, "r") as keystore:
        account = Account(json.load(keystore), password, keystore_file)

    assert account.privkey, "Could not decode keystore file: wrong password"
    assert account.address, "Could not decode keystore file: no 'address' field found"
    print("Using account:", to_checksum_address(account.address))

    client = JSONRPCClient(
        web3, account.privkey, block_num_confirmations=DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
    )

    targets = [t.strip() for t in targets_file]
    balance = client.balance(client.address)

    balance_needed = len(targets) * eth_amount
    if balance_needed * WEI_TO_ETH > balance:
        print(
            "Not enough balance to fund {} accounts with {} eth each. Need {}, have {}".format(
                len(targets), eth_amount, balance_needed, balance / WEI_TO_ETH
            )
        )

    print("Sending {} eth to:".format(eth_amount))

    for target in targets:
        print("  - {}".format(target))
        gas_price = web3.eth.gasPrice  # pylint: disable=no-member
        client.transact(
            EthTransfer(
                to_address=to_canonical_address(target),
                value=eth_amount * WEI_TO_ETH,
                gas_price=gas_price,
            )
        )


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
