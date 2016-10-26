# -*- coding: utf-8 -*-
import os
import sys
import json
import getpass

from pyethapp.accounts import Account


def find_datadir():
    home = os.path.expanduser("~")
    datadir = None
    if sys.platform.startswith('linux'):
        datadir = os.path.join(home, '.ethereum')
    elif sys.platform == 'darwin':
        datadir = os.path.join(home, 'Library', 'Ethereum')
    else:
        raise RuntimeError('Unsupported Operating System')

    if os.path.isdir(datadir) is False:
        return None
    return datadir


def find_keystoredir():
    datadir = find_datadir()
    if datadir is None:
        # can't find a data directory in the system
        return None
    keystore_path = os.path.join(datadir, 'keystore')
    if not os.path.exists(keystore_path):
        # can't find a keystore under the found data directory
        return None
    return keystore_path


class AccountManager:

    def __init__(self, keystore_path=None):
        self.accounts = {}
        self.keystore_path = keystore_path

    def get_accounts(self):
        """Find all the accounts the user has locally and return their addresses

        :return dict: A dictionary with the addresses of the accounts of the user
                      as the key and the filenames as the value
        """
        if self.accounts:
            return self.accounts

        if self.keystore_path is None:
            self.keystore_path = find_keystoredir()
        if self.keystore_path is None:
            # can't find a data directory in the system
            return {}

        acc_dict = {}
        for f in os.listdir(self.keystore_path):
            fullpath = os.path.join(self.keystore_path, f)
            if os.path.isfile(fullpath):
                with open(fullpath) as data_file:
                    data = json.load(data_file)
                    acc_dict[str(data['address'])] = str(fullpath)

        self.accounts = acc_dict
        return acc_dict

    def address_in_keystore(self, address):
        if address is not None and address.startswith('0x'):
            address = address[2:]

        accounts = self.get_accounts()
        return address in accounts

    def get_privkey(self, address, password=None):
        """Find the keystore file for an account, unlock it and get the private key

        :param str address: The Ethereum address for which to find the keyfile in the system
        :param str password: Mostly for testing purposes. A password can be provided
                             as the function argument here. If it's not then the
                             user is interactively queried for one.
        :return str: The private key associated with the address
        """

        if address.startswith('0x'):
            address = address[2:]

        if not self.address_in_keystore(address):
            raise ValueError("Keystore file not found for %s" % address)

        with open(self.accounts[address]) as data_file:
            data = json.load(data_file)

        # Since file was found prompt for a password if not already given
        if password is None:
            password = getpass.getpass("Enter the password to unlock %s: " % address)
        acc = Account(data, password, self.accounts[address])
        return acc.privkey
