# -*- coding: utf-8 -*-
from binascii import hexlify

from ethereum.tools._solidity import compile_file

from raiden.network.rpc.client import JSONRPCClient
from raiden.settings import GAS_PRICE
from raiden.utils import get_contract_path, sha3


def connect(host='127.0.0.1', port=8545):
    """Create a jsonrpcclient instance, using the 'zero-privatekey'. """
    client = JSONRPCClient(
        host,
        port,
        privkey=b'1' * 64,
    )
    return client


def create_and_distribute_token(
        client,
        receivers,
        amount_per_receiver=1000,
        name=None,
        gasprice=GAS_PRICE,
        timeout=120):
    """Create a new ERC-20 token and distribute it among `receivers`.
    If `name` is None, the name will be derived from hashing all receivers.
    """
    name = name or hexlify(sha3(''.join(receivers).encode()))
    contract_path = get_contract_path('HumanStandardToken.sol')
    token_proxy = client.deploy_solidity_contract(
        client.sender,
        'HumanStandardToken',
        compile_file(contract_path),
        dict(),
        (
            len(receivers) * amount_per_receiver,
            name,
            2,  # decimals
            name[:4].upper()  # symbol
        ),
        contract_path=contract_path,
        gasprice=gasprice,
        timeout=timeout
    )
    for receiver in receivers:
        token_proxy.transact('transfer', receiver, amount_per_receiver)
    return hexlify(token_proxy.contract_address)
