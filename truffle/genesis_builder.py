from ethereum.utils import sha3, privtoaddr, encode_hex, denoms

CLUSTER_NAME = 'raiden'

GENESIS_STUB = {
    'config': {
        'homesteadBlock': 1
    },
    'nonce': '0x0000000000000042',
    'mixhash': '0x0000000000000000000000000000000000000000000000000000000000000000',
    'difficulty': '0x4000',
    'coinbase': '0x0000000000000000000000000000000000000000',
    'timestamp': '0x00',
    'parentHash': '0x0000000000000000000000000000000000000000000000000000000000000000',
    'extraData': CLUSTER_NAME,
    'gasLimit': '0xfffffffff'
}


def generate_accounts(seeds):
    """Create private keys and addresses for all seeds.
    """
    return {
        seed: dict(
            privatekey=encode_hex(sha3(seed)),
            address=encode_hex(privtoaddr(sha3(seed)))
        ) for seed in seeds}


def mk_genesis(accounts, initial_alloc=denoms.ether * 100000000):
    """
    Create a genesis-block dict with allocation for all `accounts`.

    :param accounts: list of account addresses (hex)
    :param initial_alloc: the amount to allocate for the `accounts`
    :return: genesis dict
    """
    genesis = GENESIS_STUB.copy()
    genesis['alloc'] = {
        account: {
            'balance': str(initial_alloc)
        }
        for account in accounts
    }
    return genesis
