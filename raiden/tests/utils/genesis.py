from eth_utils import encode_hex

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
    'extraData': encode_hex(b'raiden'),
    'gasLimit': GAS_LIMIT_HEX,
    # add precompiled addresses with minimal balance to avoid deletion
    'alloc': {'%040x' % precompiled: {'balance': '0x1'} for precompiled in range(256)},
}
PARITY_CHAIN_SPEC_STUB = {
    "name": "RaidenTestChain",
    "engine": {
        "authorityRound": {
            "params": {
                "stepDuration": 3,
            },
        },
    },
    "params": {
        "gasLimitBoundDivisor": "0x0400",
        "maximumExtraDataSize": "0x20",
        "minGasLimit": "0x1388",
        "networkID": 337,
        "eip155Transition": "0x0",
        "eip98Transition": "0x7fffffffffffff",
        "eip140Transition": "0x0",
        "eip211Transition": "0x0",
        "eip214Transition": "0x0",
        "eip658Transition": "0x0",
    },
    "genesis": {
        "seal": {
            "authorityRound": {
                "step": "0x0",
                "signature": (
                    "0x00000000000000000000000000000000000000000000000000000000000000000"
                    "00000000000000000000000000000000000000000000000000000000000000000"
                ),
            },
        },
        "difficulty": "0x20000",
        "author": "0x0000000000000000000000000000000000000000",
        "timestamp": "0x00",
        "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "gasLimit": "0x2540BE400",
    },
    "accounts": {
        "0x0000000000000000000000000000000000000001": {
            "balance": "1",
            "builtin": {
                "name": "ecrecover",
                "pricing": {"linear": {"base": 3000, "word": 0}},
            },
        },
        "0x0000000000000000000000000000000000000002": {
            "balance": "1",
            "builtin": {
                "name": "sha256",
                "pricing": {"linear": {"base": 60, "word": 12}},
            },
        },
        "0x0000000000000000000000000000000000000003": {
            "balance": "1",
            "builtin": {
                "name": "ripemd160",
                "pricing": {"linear": {"base": 600, "word": 120}},
            },
        },
        "0x0000000000000000000000000000000000000004": {
            "balance": "1",
            "builtin": {
                "name": "identity",
                "pricing": {"linear": {"base": 15, "word": 3}},
            },
        },
    },
}
