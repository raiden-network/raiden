import json
import os
import sys
from typing import Dict, Optional

import structlog
from eth_keyfile import decode_keyfile_json
from eth_utils import decode_hex, encode_hex, to_canonical_address

from raiden.exceptions import RaidenError
from raiden.utils.formatting import to_checksum_address
from raiden.utils.keys import privatekey_to_address, privatekey_to_publickey
from raiden.utils.typing import Address, AddressHex, PrivateKey, PublicKey

log = structlog.get_logger(__name__)


class InvalidAccountFile(Exception):
    """Thrown when a file is not a valid keystore account file"""

    pass


class KeystoreFileNotFound(RaidenError):
    """A keystore file for a user provided account could not be found."""


class KeystoreAuthenticationError(RaidenError):
    """The provided password could not authenticated the ethereum keystore."""


def _find_datadir() -> Optional[str]:  # pragma: no cover
    home = os.path.expanduser("~")
    if home == "~":  # Could not expand user path
        return None
    if sys.platform == "darwin":
        datadir = os.path.join(home, "Library", "Ethereum")
    # NOTE: Not really sure about cygwin here
    elif sys.platform == "win32" or sys.platform == "cygwin":
        datadir = os.path.join(home, "AppData", "Roaming", "Ethereum")
    elif os.name == "posix":
        datadir = os.path.join(home, ".ethereum")
    else:
        raise RuntimeError("Unsupported Operating System")

    if not os.path.isdir(datadir):
        return None
    return datadir


def _find_keystoredir() -> Optional[str]:  # pragma: no cover
    datadir = _find_datadir()
    if datadir is None:
        # can't find a data directory in the system
        return None
    keystore_path = os.path.join(datadir, "keystore")
    if not os.path.exists(keystore_path):
        # can't find a keystore under the found data directory
        return None
    return keystore_path


class AccountManager:
    def __init__(self, keystore_path: str = None):
        self.keystore_path = keystore_path
        self.accounts: Dict[AddressHex, str] = {}
        if self.keystore_path is None:
            self.keystore_path = _find_keystoredir()
        if self.keystore_path is not None:

            try:
                files = os.listdir(self.keystore_path)
            except OSError as ex:
                msg = "Unable to list the specified directory"
                log.error("OsError", msg=msg, path=self.keystore_path, ex=ex)
                return

            for f in files:
                fullpath = os.path.join(self.keystore_path, f)
                if os.path.isfile(fullpath):
                    try:
                        with open(fullpath) as data_file:
                            data = json.load(data_file)
                            if not isinstance(data, dict) or "address" not in data:
                                # we expect a dict in specific format.
                                # Anything else is not a keyfile
                                raise InvalidAccountFile(f"Invalid keystore file {fullpath}")
                            address = to_checksum_address(to_canonical_address(data["address"]))
                            self.accounts[address] = str(fullpath)
                    except OSError as ex:
                        msg = "Can not read account file (errno=%s)" % ex.errno
                        log.warning(msg, path=fullpath, ex=ex)
                    except (
                        json.JSONDecodeError,
                        KeyError,
                        UnicodeDecodeError,
                        InvalidAccountFile,
                    ) as ex:
                        # Invalid file - skip
                        if f.startswith("UTC--"):
                            # Should be a valid account file - warn user
                            msg = "Invalid account file"
                            if isinstance(ex, json.decoder.JSONDecodeError):
                                msg = "The account file is not valid JSON format"
                            log.warning(msg, path=fullpath, ex=ex)

    def address_in_keystore(self, address: AddressHex) -> bool:
        return address in self.accounts

    def get_privkey(self, address: AddressHex, password: str) -> PrivateKey:
        """Find the keystore file for an account, unlock it and get the private key

        Args:
            address: The Ethereum address for which to find the keyfile in the system
            password: Mostly for testing purposes. A password can be provided
                           as the function argument here. If it's not then the
                           user is interactively queried for one.
        Returns
            The private key associated with the address
        """
        if not self.address_in_keystore(address):
            raise KeystoreFileNotFound("Keystore file not found for %s" % address)

        with open(self.accounts[address]) as data_file:
            data = json.load(data_file)

        acc = Account(data, password, self.accounts[address])

        assert acc.privkey is not None, f"Private key of account ({address}) not known."
        return acc.privkey


class Account:
    """Represents an account."""

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
            self._address = Address(decode_hex(self.keystore["address"]))
        except KeyError:
            pass

        if password is not None:
            self.unlock(password)

    def unlock(self, password: str) -> None:
        """Unlock the account with a password.

        If the account is already unlocked, nothing happens, even if the password is wrong.

        Raises:
            ValueError: (originating in ethereum.keys) if the password is wrong
            (and the account is locked)
        """
        if self.locked:
            self._privkey = decode_keyfile_json(self.keystore, password.encode("UTF-8"))
            self.locked = False
            # get address such that it stays accessible after a subsequent lock
            self._fill_address()

    def lock(self) -> None:
        """Relock an unlocked account.

        This method sets `account.privkey` to `None` (unlike `account.address` which is preserved).
        After calling this method, both `account.privkey` and `account.pubkey` are `None.
        `account.address` stays unchanged, even if it has been derived from the private key.
        """
        self._privkey = None
        self.locked = True

    def _fill_address(self) -> None:
        if "address" in self.keystore:
            self._address = Address(decode_hex(self.keystore["address"]))
        elif not self.locked:
            assert self.privkey is not None, "`privkey` not set, maybe call `unlock` before."
            self._address = privatekey_to_address(self.privkey)

    @property
    def privkey(self) -> Optional[PrivateKey]:
        """The account's private key or `None` if the account is locked"""
        if not self.locked:
            return self._privkey
        return None

    @property
    def pubkey(self) -> Optional[PublicKey]:
        """The account's public key or `None` if the account is locked"""
        if not self.locked:
            assert self.privkey is not None, "`privkey` not set, maybe call `unlock` before."
            return privatekey_to_publickey(self.privkey)

        return None

    @property
    def address(self) -> Optional[Address]:
        """The account's address or `None` if the address is not stored in the key file and cannot
        be reconstructed (because the account is locked)
        """
        if not self._address:
            self._fill_address()

        return self._address

    @property
    def uuid(self) -> Optional[str]:
        """An optional unique identifier, formatted according to UUID version 4, or `None` if the
        account does not have an id
        """
        try:
            return self.keystore["id"]
        except KeyError:
            return None

    @uuid.setter
    def uuid(self, value: Optional[str]) -> None:
        """Set the UUID. Set it to `None` in order to remove it."""
        if value is not None:
            self.keystore["id"] = value
        elif "id" in self.keystore:
            self.keystore.pop("id")

    def __repr__(self) -> str:
        if self.address is not None:
            return f"<Account(address={encode_hex(self.address)}, id={self.uuid})>"

        return f"<Account(address=???, id={self.uuid})>"
