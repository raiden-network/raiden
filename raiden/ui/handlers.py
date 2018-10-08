import sys

import click
from eth_utils import to_checksum_address

from raiden.utils import typing


def handle_contract_version_mismatch(name: str, address: typing.Address) -> None:
    hex_addr = to_checksum_address(address)
    click.secho(
        f'Error: Provided {name} {hex_addr} contract version mismatch. '
        'Please update your Raiden installation.',
        fg='red',
    )
    sys.exit(1)


def handle_contract_no_code(name: str, address: typing.Address) -> None:
    hex_addr = to_checksum_address(address)
    click.secho(f'Error: Provided {name} {hex_addr} contract does not contain code', fg='red')
    sys.exit(1)


def handle_contract_wrong_address(name: str, address: typing.Address) -> None:
    hex_addr = to_checksum_address(address)
    click.secho(
        f'Error: Provided address {hex_addr} for {name} contract'
        ' does not contain expected code.',
        fg='red',
    )
    sys.exit(1)
