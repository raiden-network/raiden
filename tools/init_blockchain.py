from pyethapp.rpc_client import JSONRPCClient
from pyethapp.jsonrpc import default_gasprice
from ethereum.utils import sha3
from ethereum._solidity import compile_file
from raiden.utils import get_contract_path
from raiden.network.rpc.client import patch_send_transaction


def connect(host="127.0.0.1",
            port=8545,
            use_ssl=False):
    """Create a jsonrpcclient instance, using the 'zero-privatekey'.
    """
    client = JSONRPCClient(host, port, privkey="1" * 64)
    patch_send_transaction(client)
    return client


def create_and_distribute_token(client, receivers,
                                amount_per_receiver=1000,
                                name=None,
                                gasprice=default_gasprice,
                                timeout=120):
    """Create a new ERC-20 token and distribute it among `receivers`.
    If `name` is None, the name will be derived from hashing all receivers.
    """
    name = name or sha3(''.join(receivers)).encode('hex')
    token_proxy = client.deploy_solidity_contract(
        client.sender,
        'HumanStandardToken',
        compile_file(get_contract_path('HumanStandardToken.sol')),
        dict()
        (
            len(receivers) * amount_per_receiver,
            name,
            2,  # decimals
            name[:4].upper()  # symbol
        ),
        gasprice=gasprice,
        timeout=timeout
    )
    for receiver in receivers:
        token_proxy.transfer(receiver, amount_per_receiver)
    return token_proxy.address.encode('hex')
