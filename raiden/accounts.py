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


def get_accounts():
    """Find all the accounts the user has locally and return their addresses

    :return dict: A dictionary with the addresses of the accounts of the user
                  as the key and the filenames as the value
    """
    keystore_path = find_keystoredir()
    if keystore_path is None:
        # can't find a data directory in the system
        return {}

    acc_dict = {}
    for f in os.listdir(keystore_path):
        fullpath = os.path.join(keystore_path, f)
        if os.path.isfile(fullpath):
            with open(fullpath) as data_file:
                data = json.load(data_file)
            acc_dict[str(data['address'])] = str(fullpath)

    return acc_dict


def get_privkey(address):
    """Find the keystore file for an account, unlock it and get the private key

    :param str address: The Ethereum address for which to find the keyfile in the system
    :return str: The private key associated with the address
    """

    if address.startswith('0x'):
        address = address[2:]

    accounts = get_accounts()
    if address not in accounts:
        raise ValueError("Keystore file not found for %s" % address)

    with open(accounts[address]) as data_file:
        data = json.load(data_file)

    # Since file was found prompt for a password
    password = getpass.getpass("Enter the password to unlock %s: " % address)
    acc = Account(data, password, accounts[address])
    return acc.privkey
