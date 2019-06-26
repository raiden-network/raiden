from eth_utils import to_checksum_address

from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.factories import HOP1


def burn_eth(rpc_client: JSONRPCClient, amount_to_leave: int = 0) -> None:
    """Burns all the ETH on the account of the given raiden service"""
    address = to_checksum_address(rpc_client.address)
    web3 = rpc_client.web3
    gas_price = web3.eth.gasPrice
    value = web3.eth.getBalance(address) - gas_price * (21000 + amount_to_leave)
    transaction_hash = rpc_client.send_transaction(to=HOP1, value=value, startgas=21000)
    rpc_client.poll(transaction_hash)
