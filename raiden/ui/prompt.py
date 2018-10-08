import sys

import click
from eth_utils import to_checksum_address

from raiden.accounts import AccountManager


def prompt_account(address_hex, keystore_path, password_file):
    accmgr = AccountManager(keystore_path)
    if not accmgr.accounts:
        click.secho(
            'No Ethereum accounts found in the provided keystore directory {}. '
            'Please provide a directory containing valid ethereum account '
            'files.'.format(keystore_path),
            fg='red',
        )
        sys.exit(1)

    if not accmgr.address_in_keystore(address_hex):
        # check if an address has been passed
        if address_hex is not None:
            click.secho(
                f"Account '{address_hex}' could not be found on the system. Aborting ...",
                fg='red',
            )
            sys.exit(1)

        addresses = list(accmgr.accounts.keys())
        formatted_addresses = [
            '[{:3d}] - {}'.format(idx, to_checksum_address(addr))
            for idx, addr in enumerate(addresses)
        ]

        should_prompt = True

        print('The following accounts were found in your machine:')
        print('')
        print('\n'.join(formatted_addresses))
        print('')

        while should_prompt:
            idx = click.prompt('Select one of them by index to continue', type=int)

            if 0 <= idx < len(addresses):
                should_prompt = False
            else:
                print('\nError: Provided index "{}" is out of bounds\n'.format(idx))

        address_hex = addresses[idx]

    password = None
    if password_file:
        password = password_file.read()
        if password != '':
            password = password.splitlines()[0]
    if password is not None:
        try:
            privatekey_bin = accmgr.get_privkey(address_hex, password)
        except ValueError:
            # ValueError exception raised if the password is incorrect
            click.secho(
                f'Incorrect password for {address_hex} in file. Aborting ...',
                fg='red',
            )
            sys.exit(1)
    else:
        unlock_tries = 3
        while True:
            try:
                privatekey_bin = accmgr.get_privkey(address_hex)
                break
            except ValueError:
                # ValueError exception raised if the password is incorrect
                if unlock_tries == 0:
                    click.secho(
                        f'Exhausted passphrase unlock attempts for {address_hex}. Aborting ...',
                        fg='red',
                    )
                    sys.exit(1)

                print(
                    'Incorrect passphrase to unlock the private key. {} tries remaining. '
                    'Please try again or kill the process to quit. '
                    'Usually Ctrl-c.'.format(unlock_tries),
                )
                unlock_tries -= 1

    return address_hex, privatekey_bin
