from raiden.constants import TRANSACTION_INTRINSIC_GAS
from raiden.network.rpc.client import EthTransfer, JSONRPCClient
from raiden.tests.utils.factories import HOP1
from raiden.utils.typing import Address


def burn_eth(rpc_client: JSONRPCClient, amount_to_leave: int = 0) -> None:
    """Burns all the ETH on the account of the given raiden service"""
    address = rpc_client.address
    web3 = rpc_client.web3
    gas_price = web3.eth.gasPrice

    # Leave enough ETH to pay for the burn transaction.
    amount_to_leave = TRANSACTION_INTRINSIC_GAS + amount_to_leave

    amount_to_burn = web3.eth.getBalance(address) - gas_price * amount_to_leave
    burn_transfer = EthTransfer(
        to_address=Address(HOP1), value=amount_to_burn, gas_price=gas_price
    )

    transaction_hash = rpc_client.transact(burn_transfer)
    rpc_client.poll_transaction(transaction_hash)
