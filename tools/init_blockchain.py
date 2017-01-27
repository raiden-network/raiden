from pyethapp.rpc_client import JSONRPCClient
from pyethapp.jsonrpc import default_gasprice
from ethereum.utils import sha3
from ethereum._solidity import compile_file
from raiden.utils import get_contract_path
from raiden.network.rpc.client import patch_send_transaction, patch_send_message


def connect(host='127.0.0.1',
            port=8545,
            use_ssl=False):
    """Create a jsonrpcclient instance, using the 'zero-privatekey'.
    """
    client = JSONRPCClient(
        host,
        port,
        privkey='1' * 64,
        print_communication=False,
        use_ssl=use_ssl,
    )
    patch_send_transaction(client)
    patch_send_message(client)
    return client


def create_and_distribute_token(
        client,
        receivers,
        amount_per_receiver=1000,
        name=None,
        gasprice=default_gasprice,
        timeout=120
):
    """Create a new ERC-20 token and distribute it among `receivers`.
    If `name` is None, the name will be derived from hashing all receivers.
    """
    name = name or sha3(''.join(receivers)).encode('hex')
    contract_path = get_contract_path('HumanStandardToken.sol')
    token_proxy = client.deploy_solidity_contract(
        client.sender,
        'HumanStandardToken',
        compile_file(contract_path),
        dict()
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
        token_proxy.transfer(receiver, amount_per_receiver)
    return token_proxy.address.encode('hex')
