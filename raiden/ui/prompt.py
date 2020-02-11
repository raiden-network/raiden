import getpass
from typing import TextIO

import click
from eth_utils import decode_hex

from raiden.accounts import AccountManager, KeystoreAuthenticationError
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import Address, AddressHex, PrivateKey


def prompt_account(account_manager: AccountManager) -> AddressHex:
    addresses = list(account_manager.accounts.keys())
    formatted_addresses = [
        "[{:3d}] - {}".format(idx, to_checksum_address(Address(decode_hex(addr))))
        for idx, addr in enumerate(addresses)
    ]

    print("The following accounts were found in your machine:")
    print("")
    print("\n".join(formatted_addresses))
    print("")

    while True:
        idx = click.prompt("Select one of them by index to continue", type=int)

        if 0 <= idx < len(addresses):
            return addresses[idx]

        print(f'\nError: Provided index "{idx}" is out of bounds\n')


def unlock_account_with_passwordfile(
    account_manager: AccountManager, address_hex: AddressHex, password_file: TextIO
) -> PrivateKey:
    password = password_file.read().strip("\r\n")

    try:
        return account_manager.get_privkey(address_hex, password.strip())
    except ValueError:
        raise KeystoreAuthenticationError(f"Incorrect password for {address_hex} in file.")


def unlock_account_with_passwordprompt(
    account_manager: AccountManager, address_hex: AddressHex
) -> PrivateKey:
    tries = 3
    for current in range(tries):
        try:
            checksum_address = to_checksum_address(Address(decode_hex(address_hex)))
            password = getpass.getpass(f"Enter the password to unlock {checksum_address}: ")
            return account_manager.get_privkey(address_hex, password)
        except ValueError:
            print(
                f"Incorrect passphrase to unlock the private key. "
                f"{current} out of {tries} tries. "
                f"Please try again or kill the process to quit. "
                f"Usually Ctrl-c."
            )

    raise KeystoreAuthenticationError(
        f"Provided Incorrect password for {address_hex} {tries} times."
    )
