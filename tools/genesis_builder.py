from binascii import hexlify

from eth_utils import denoms, encode_hex

from raiden.tests.utils.genesis import GENESIS_STUB
from raiden.utils import privatekey_to_address, sha3

CLUSTER_NAME = b'raiden'


def generate_accounts(seeds):
    """Create private keys and addresses for all seeds.
    """
    return {
        seed: {
            'privatekey': encode_hex(sha3(seed)),
            'address': encode_hex(privatekey_to_address(sha3(seed))),
        }
        for seed in seeds
    }


def mk_genesis(accounts, initial_alloc=denoms.ether * 100000000):
    """
    Create a genesis-block dict with allocation for all `accounts`.

    :param accounts: list of account addresses (hex)
    :param initial_alloc: the amount to allocate for the `accounts`
    :return: genesis dict
    """
    genesis = GENESIS_STUB.copy()
    genesis['extraData'] = '0x' + hexlify(CLUSTER_NAME).decode()
    genesis['alloc'].update({
        account: {
            'balance': str(initial_alloc),
        }
        for account in accounts
    })
    # add the one-privatekey account ("1" * 64) for convenience
    genesis['alloc']['19e7e376e7c213b7e7e7e46cc70a5dd086daff2a'] = dict(balance=str(initial_alloc))
    return genesis
