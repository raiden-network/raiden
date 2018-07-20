from eth_utils import to_checksum_address

from raiden.tests.utils.factories import HOP1


def burn_all_eth(raiden_service):
    """Burns all the ETH on the account of the given raiden service"""
    address = to_checksum_address(raiden_service.address)
    client = raiden_service.chain.client
    web3 = client.web3
    gas_price = web3.eth.gasPrice
    value = web3.eth.getBalance(address) - gas_price * 21000
    transaction_hash = client.send_transaction(
        to=HOP1,
        value=value,
        startgas=21000,
    )
    client.poll(transaction_hash)
