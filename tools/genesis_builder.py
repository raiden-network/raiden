# -*- coding: utf-8 -*-
from ethereum.utils import sha3, encode_hex, denoms

from raiden.utils import privatekey_to_address
from raiden.tests.utils.blockchain import GENESIS_STUB

CLUSTER_NAME = 'raiden'


def generate_accounts(seeds):
    """Create private keys and addresses for all seeds.
    """
    return {
        seed: dict(
            privatekey=encode_hex(sha3(seed)),
            address=encode_hex(privatekey_to_address(sha3(seed)))
        ) for seed in seeds}


def mk_genesis(accounts, initial_alloc=denoms.ether * 100000000):
    """
    Create a genesis-block dict with allocation for all `accounts`.

    :param accounts: list of account addresses (hex)
    :param initial_alloc: the amount to allocate for the `accounts`
    :return: genesis dict
    """
    genesis = GENESIS_STUB.copy()
    genesis['extraData'] = CLUSTER_NAME
    genesis['alloc'] = {
        account: {
            'balance': str(initial_alloc)
        }
        for account in accounts
    }
    # add the one-privatekey account ("1" * 64) for convenience
    genesis['alloc']['19e7e376e7c213b7e7e7e46cc70a5dd086daff2a'] = dict(balance=str(initial_alloc))
    return genesis
