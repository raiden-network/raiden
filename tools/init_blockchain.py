import gevent
from eth_utils import encode_hex, to_checksum_address
from web3 import HTTPProvider, Web3

from raiden.network.rpc.client import JSONRPCClient
from raiden.utils import get_contract_path, sha3
from raiden.utils.solc import compile_files_cwd


def connect(host='127.0.0.1', port=8545):
    """Create a jsonrpcclient instance, using the 'zero-privatekey'. """
    privkey = b'1' * 64
    web3 = Web3(HTTPProvider(f'http://{host}:{port}'))
    client = JSONRPCClient(web3, privkey)
    return client


def create_and_distribute_token(
        client,
        receivers,
        amount_per_receiver=1000,
        name=None,
        timeout=120):
    """Create a new ERC-20 token and distribute it among `receivers`.
    If `name` is None, the name will be derived from hashing all receivers.
    """
    name = name or encode_hex(sha3(''.join(receivers).encode()))
    contract_path = get_contract_path('HumanStandardToken.sol')

    with gevent.Timeout(timeout):
        token_proxy = client.deploy_solidity_contract(
            'HumanStandardToken',
            compile_files_cwd([contract_path]),
            dict(),
            (
                len(receivers) * amount_per_receiver,
                name,
                2,  # decimals
                name[:4].upper(),  # symbol
            ),
            contract_path=contract_path,
        )

    for receiver in receivers:
        token_proxy.transact('transfer', receiver, amount_per_receiver)
    return to_checksum_address(token_proxy.contract_address)
