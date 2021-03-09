#!/usr/bin/env python3
import os
import sys

import click
from eth_utils import encode_hex, to_normalized_address

from raiden.accounts import AccountManager
from raiden.utils.cli import ADDRESS_TYPE
from raiden.utils.formatting import to_checksum_address
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import Address


@click.command()
@click.option(
    "--address",
    help="The ethereum address for which to get a login",
    type=ADDRESS_TYPE,
    required=True,
)
@click.password_option(
    "--password",
    confirmation_prompt=False,
    help="Password to unlock the keystore file.",
    default="",
)
def get_login(address: Address, password: str) -> None:
    path = os.path.expanduser("~/.ethereum/keystore")
    if sys.platform.startswith("darwin"):
        path = os.path.expanduser("~/Library/Ethereum/keystore")

    am = AccountManager(path)
    signer = LocalSigner(am.get_privkey(to_checksum_address(address), password))

    print(f"Username: {to_normalized_address(address)}")
    print("Password:")
    for i in range(1, 5):
        print(
            f"\ttransport {i:02d}:",
            encode_hex(signer.sign(f"transport.transport{i:02d}.raiden.network".encode())),
        )


if __name__ == "__main__":
    get_login()  # pylint: disable=no-value-for-parameter
