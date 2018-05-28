# -*- coding: utf-8 -*-
from ethereum.tools import tester

from raiden.tests.utils.blockchain import DEFAULT_BALANCE
from raiden.utils import privatekey_to_address


class InvalidKey(str):
    # using an invalid key as the proxies default_key to force the user to set
    # `sender`. The reason for this is that too many tests were mixing the
    # wrong key, the alternative was to instantiate a proxy per key, which was
    # adding to much code-bloat, using an invalid key we effectvelly disable
    # the "feature" of the ABIContract to use a default key, making all the
    # calls explicit, this is intentional!
    def __getitem__(self, key):
        # please provide an explicit key while testing with tester
        raise Exception('sender key was not set')


INVALID_KEY = InvalidKey('default_key_was_not_set')


def create_tester_chain(deploy_key, private_keys, tester_blockgas_limit):
    alloc = {}

    for privkey in [deploy_key] + private_keys:
        address = privatekey_to_address(privkey)
        alloc[address] = {
            'balance': DEFAULT_BALANCE,
        }

    for account in tester.accounts:
        alloc[account] = {
            'balance': DEFAULT_BALANCE,
        }

    tester.k0 = deploy_key
    tester.a0 = privatekey_to_address(deploy_key)

    return tester.Chain(alloc)
