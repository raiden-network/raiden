#!/usr/bin/env python3
import os

import click
from eth_utils import encode_hex

from raiden.accounts import AccountManager
from raiden.utils.cli import ADDRESS_TYPE
from raiden.utils.formatting import to_checksum_address
from raiden.utils.signer import LocalSigner


@click.command()
@click.option(
    "--address",
    help="The ethereum address for which to get a login",
    type=ADDRESS_TYPE,
    required=True,
)
@click.password_option(
    "--password", confirmation_prompt=False, help="Password to unlock the keystore file."
)
def get_login(address, password) -> None:
    am = AccountManager(os.path.expanduser("~/.ethereum/keystore"))
    signer = LocalSigner(am.get_privkey(to_checksum_address(address), password))
    for i in range(1, 5):
        print(f"{i:02d}:", encode_hex(signer.sign(f"transport{i:02d}.raiden.network".encode())))


if __name__ == "__main__":
    get_login()  # pylint: disable=no-value-for-parameter
