#!/usr/bin/env python
import os

import click
import IPython
from eth_utils import encode_hex, to_checksum_address, to_normalized_address

from raiden.accounts import AccountManager
from raiden.network.transport.matrix.client import GMatrixHttpApi
from raiden.utils.cli import ADDRESS_TYPE
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
@click.option(
    "--server", help="Matrix server to connect to", default="https://transport01.raiden.network"
)
def matrix_api_shell(address, password, server):
    am = AccountManager(os.path.expanduser("~/.ethereum/keystore"))
    signer = LocalSigner(am.get_privkey(to_checksum_address(address), password))
    server_name = server.split("//")[1]
    matrix_password = encode_hex(signer.sign(server_name.encode()))

    api = GMatrixHttpApi(server)
    resp = api.login(
        "m.login.password", user=to_normalized_address(address), password=matrix_password
    )
    api.token = resp["access_token"]
    IPython.embed(header=f"Use the `api` object to interact with matrix on {server}.")


if __name__ == "__main__":
    matrix_api_shell()  # pylint: disable=no-value-for-parameter
