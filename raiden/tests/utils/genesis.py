from binascii import hexlify

from raiden.settings import GAS_LIMIT_HEX

GENESIS_STUB = {
    'config': {
        'homesteadBlock': 0,
        'eip150Block': 0,
        'eip150Hash': '0x0000000000000000000000000000000000000000000000000000000000000000',
        'eip155Block': 0,
        'eip158Block': 0,
        'ByzantiumBlock': 0,
    },
    'nonce': '0x0',
    'mixhash': '0x0000000000000000000000000000000000000000000000000000000000000000',
    'difficulty': '0x1',
    'coinbase': '0x0000000000000000000000000000000000000000',
    'timestamp': '0x00',
    'parentHash': '0x0000000000000000000000000000000000000000000000000000000000000000',
    'extraData': '0x' + hexlify(b'raiden').decode(),
    'gasLimit': GAS_LIMIT_HEX,
    # add precompiled addresses with minimal balance to avoid deletion
    'alloc': {'%040x' % precompiled: {'balance': '0x1'} for precompiled in range(256)},
}
