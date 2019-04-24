import getpass
import sys
from typing import TextIO

import click
from eth_utils import to_checksum_address

from raiden.accounts import AccountManager
from raiden.utils.typing import AddressHex, PrivateKey


def check_has_accounts(account_manager: AccountManager) -> None:
    if not account_manager.accounts:
        msg = (
            f'No Ethereum accounts found in the provided keystore directory '
            f'{account_manager.keystore_path}. Please provide a directory '
            f'containing valid ethereum account files.'
        )
        click.secho(msg, fg='red')
        sys.exit(1)


def check_account(account_manager: AccountManager, address_hex: AddressHex) -> None:
    if not account_manager.address_in_keystore(address_hex):
        click.secho(
            f"Account '{address_hex}' could not be found on the system. Aborting ...",
            fg='red',
        )
        sys.exit(1)


def prompt_account(account_manager: AccountManager) -> AddressHex:
    addresses = list(account_manager.accounts.keys())
    formatted_addresses = [
        '[{:3d}] - {}'.format(idx, to_checksum_address(addr))
        for idx, addr in enumerate(addresses)
    ]

    print('The following accounts were found in your machine:')
    print('')
    print('\n'.join(formatted_addresses))
    print('')

    while True:
        idx = click.prompt('Select one of them by index to continue', type=int)

        if 0 <= idx < len(addresses):
            return addresses[idx]

        print('\nError: Provided index "{}" is out of bounds\n'.format(idx))


def unlock_account_with_passwordfile(
        account_manager: AccountManager,
        address_hex: AddressHex,
        password_file: TextIO,
) -> PrivateKey:
    password = password_file.read().strip('\r\n')

    try:
        return account_manager.get_privkey(address_hex, password)
    except ValueError:
        click.secho(
            f'Incorrect password for {address_hex} in file. Aborting ...',
            fg='red',
        )
        sys.exit(1)


def unlock_account_with_passwordprompt(
        account_manager: AccountManager,
        address_hex: AddressHex,
) -> PrivateKey:
    tries = 3
    for current in range(tries):
        try:
            password = getpass.getpass(
                f'Enter the password to unlock {address_hex}: ',
            )
            return account_manager.get_privkey(address_hex, password)
        except ValueError:
            print(
                f'Incorrect passphrase to unlock the private key. '
                f'{current} out of {tries} tries. '
                f'Please try again or kill the process to quit. '
                f'Usually Ctrl-c.',
            )

    sys.exit(1)
