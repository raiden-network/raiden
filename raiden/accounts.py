import getpass
import json
import os
import sys
from typing import Dict, Optional

import structlog
from eth_keyfile import decode_keyfile_json
from eth_utils import add_0x_prefix, decode_hex, encode_hex, remove_0x_prefix, to_checksum_address

from raiden.utils import privatekey_to_address, privtopub
from raiden.utils.typing import AddressHex

log = structlog.get_logger(__name__)


def _find_datadir() -> str:
    home = os.path.expanduser('~')
    if home == '~':  # Could not expand user path
        return None
    if sys.platform == 'darwin':
        datadir = os.path.join(home, 'Library', 'Ethereum')
    # NOTE: Not really sure about cygwin here
    elif sys.platform == 'win32' or sys.platform == 'cygwin':
        datadir = os.path.join(home, 'AppData', 'Roaming', 'Ethereum')
    elif os.name == 'posix':
        datadir = os.path.join(home, '.ethereum')
    else:
        raise RuntimeError('Unsupported Operating System')

    if not os.path.isdir(datadir):
        return None
    return datadir


def _find_keystoredir() -> str:
    datadir = _find_datadir()
    if datadir is None:
        # can't find a data directory in the system
        return None
    keystore_path = os.path.join(datadir, 'keystore')
    if not os.path.exists(keystore_path):
        # can't find a keystore under the found data directory
        return None
    return keystore_path


def check_keystore_json(jsondata: Dict) -> bool:
    """ Check if ``jsondata`` has the structure of a keystore file version 3.

    Note that this test is not complete, e.g. it doesn't check key derivation or cipher parameters.
    Copied from https://github.com/vbuterin/pybitcointools

    Args:
        jsondata: Dictionary containing the data from the json file

    Returns:
        `True` if the data appears to be valid, otherwise `False`
    """
    if 'crypto' not in jsondata and 'Crypto' not in jsondata:
        return False
    if 'version' not in jsondata:
        return False
    if jsondata['version'] != 3:
        return False

    crypto = jsondata.get('crypto', jsondata.get('Crypto'))
    if 'cipher' not in crypto:
        return False
    if 'ciphertext' not in crypto:
        return False
    if 'kdf' not in crypto:
        return False
    if 'mac' not in crypto:
        return False
    return True


class AccountManager:
    def __init__(self, keystore_path: str = None):
        self.keystore_path = keystore_path
        self.accounts = {}
        if self.keystore_path is None:
            self.keystore_path = _find_keystoredir()
        if self.keystore_path is not None:

            try:
                files = os.listdir(self.keystore_path)
            except OSError as ex:
                msg = 'Unable to list the specified directory'
                log.error('OsError', msg=msg, path=self.keystore_path, ex=ex)
                return

            for f in files:
                fullpath = os.path.join(self.keystore_path, f)
                if os.path.isfile(fullpath):
                    try:
                        with open(fullpath) as data_file:
                            data = json.load(data_file)
                            address = add_0x_prefix(str(data['address']).lower())
                            self.accounts[address] = str(fullpath)
                    except (
                        IOError,
                        json.JSONDecodeError,
                        KeyError,
                        OSError,
                        UnicodeDecodeError,
                    ) as ex:
                        # Invalid file - skip
                        if f.startswith('UTC--'):
                            # Should be a valid account file - warn user
                            msg = 'Invalid account file'
                            if isinstance(ex, IOError) or isinstance(ex, OSError):
                                msg = 'Can not read account file (errno=%s)' % ex.errno
                            if isinstance(ex, json.decoder.JSONDecodeError):
                                msg = 'The account file is not valid JSON format'
                            log.warning(msg, path=fullpath, ex=ex)

    def address_in_keystore(self, address: Optional[AddressHex]) -> bool:
        if address is None:
            return False

        address = add_0x_prefix(address)

        return address.lower() in self.accounts

    def get_privkey(self, address: AddressHex, password: str = None) -> str:
        """Find the keystore file for an account, unlock it and get the private key

        Args:
            address(str): The Ethereum address for which to find the keyfile in the system
            password(str): Mostly for testing purposes. A password can be provided
                           as the function argument here. If it's not then the
                           user is interactively queried for one.
        Returns
            str: The private key associated with the address
        """

        address = add_0x_prefix(address).lower()

        if not self.address_in_keystore(address):
            raise ValueError('Keystore file not found for %s' % address)

        with open(self.accounts[address]) as data_file:
            data = json.load(data_file)

        # Since file was found prompt for a password if not already given
        if password is None:
            password = getpass.getpass(
                f'Enter the password to unlock {to_checksum_address(address)}: ',
            )
        acc = Account(data, password, self.accounts[address])
        return acc.privkey


class Account:
    """Represents an account.  """

    def __init__(self, keystore: Dict, password: str = None, path: str = None):
        """
        Args:
            keystore: the key store as a dictionary (as decoded from json)
            password: The password used to unlock the keystore
            path: absolute path to the associated keystore file (`None` for in-memory accounts)
        """
        if path is not None:
            path = os.path.abspath(path)

        self.keystore = keystore
        self.locked = True
        self.path = path
        self._privkey = None
        self._address = None

        try:
            self._address = decode_hex(self.keystore['address'])
        except KeyError:
            pass

        if password is not None:
            self.unlock(password)

    @classmethod
    def load(cls, path: str, password: str = None) -> 'Account':
        """Load an account from a keystore file.

        Args:
            path: full path to the keyfile
            password: the password to decrypt the key file or `None` to leave it encrypted
        """
        with open(path) as f:
            keystore = json.load(f)
        if not check_keystore_json(keystore):
            raise ValueError('Invalid keystore file')
        return Account(keystore, password, path=path)

    def dump(self, include_address=True, include_id=True) -> str:
        """Dump the keystore for later disk storage.

        The result inherits the entries `'crypto'` and `'version`' from `account.keystore`, and
        adds `'address'` and `'id'` in accordance with the parameters `'include_address'` and
        `'include_id`'.

        If address or id are not known, they are not added, even if requested.

        Args:
            include_address: flag denoting if the address should be included or not
            include_id: flag denoting if the id should be included or not
        """
        d = {
            'crypto': self.keystore['crypto'],
            'version': self.keystore['version'],
        }
        if include_address and self.address is not None:
            d['address'] = remove_0x_prefix(encode_hex(self.address))
        if include_id and self.uuid is not None:
            d['id'] = self.uuid
        return json.dumps(d)

    def unlock(self, password: str):
        """Unlock the account with a password.

        If the account is already unlocked, nothing happens, even if the password is wrong.

        Raises:
            ValueError: (originating in ethereum.keys) if the password is wrong
            (and the account is locked)
        """
        if self.locked:
            self._privkey = decode_keyfile_json(self.keystore, password.encode('UTF-8'))
            self.locked = False
            self.address  # get address such that it stays accessible after a subsequent lock

    def lock(self):
        """Relock an unlocked account.

        This method sets `account.privkey` to `None` (unlike `account.address` which is preserved).
        After calling this method, both `account.privkey` and `account.pubkey` are `None.
        `account.address` stays unchanged, even if it has been derived from the private key.
        """
        self._privkey = None
        self.locked = True

    @property
    def privkey(self):
        """The account's private key or `None` if the account is locked"""
        if not self.locked:
            return self._privkey
        return None

    @property
    def pubkey(self):
        """The account's public key or `None` if the account is locked"""
        if not self.locked:
            return privtopub(self.privkey)

        return None

    @property
    def address(self):
        """The account's address or `None` if the address is not stored in the key file and cannot
        be reconstructed (because the account is locked)
        """
        if self._address:
            pass
        elif 'address' in self.keystore:
            self._address = decode_hex(self.keystore['address'])
        elif not self.locked:
            self._address = privatekey_to_address(self.privkey)
        else:
            return None
        return self._address

    @property
    def uuid(self):
        """An optional unique identifier, formatted according to UUID version 4, or `None` if the
        account does not have an id
        """
        try:
            return self.keystore['id']
        except KeyError:
            return None

    @uuid.setter
    def uuid(self, value):
        """Set the UUID. Set it to `None` in order to remove it."""
        if value is not None:
            self.keystore['id'] = value
        elif 'id' in self.keystore:
            self.keystore.pop('id')

    def __repr__(self):
        if self.address is not None:
            address = encode_hex(self.address)
        else:
            address = '?'
        return '<Account(address={address}, id={id})>'.format(address=address, id=self.uuid)
