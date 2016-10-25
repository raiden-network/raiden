# -*- coding: utf-8 -*-
import os
import sys
import json

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

    # TODO: f.rsplit() should be changed to actually read account from the
    # file itself since the name of the file may have been renamed to whatever
    accounts = [(f.rsplit('--', 1)[-1], f) for f in os.listdir(keystore_path)
                if os.path.isfile(os.path.join(keystore_path, f))]
    acc_dict = {}
    for acc, f in accounts:
        acc_dict[acc] = f
    return acc_dict


def unlock_account(address):
    """Find the keystore file for an account and unlock it

    :param str address: The Ethereum address for which to find the keyfile in the system
    """
    address = address.lstip('0x')

    accounts = get_accounts()
    if address not in accounts:
        # Address not found
        return None

    password = 1
    with open(accounts['address']) as data_file:
        data = json.load(data_file)
    acc = Account(data, password)
