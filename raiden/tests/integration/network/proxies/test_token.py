from eth_utils import to_canonical_address

from raiden.constants import BLOCK_ID_LATEST
from raiden.network.proxies.token import Token
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.smartcontracts import is_tx_hash_bytes
from raiden.utils.keys import privatekey_to_address


def test_token(deploy_client, token_proxy, private_keys, web3, contract_manager):
    privkey = private_keys[1]
    address = privatekey_to_address(privkey)
    address = to_canonical_address(address)
    other_client = JSONRPCClient(web3, privkey)
    other_token_proxy = Token(
        jsonrpc_client=other_client,
        token_address=to_canonical_address(token_proxy.proxy.address),
        contract_manager=contract_manager,
        block_identifier=BLOCK_ID_LATEST,
    )

    # send some funds from deployer to generated address
    transfer_funds = 100
    transaction_hash = token_proxy.transfer(address, transfer_funds)
    assert is_tx_hash_bytes(transaction_hash)
    assert transfer_funds == token_proxy.balance_of(address)
    allow_funds = 100

    transaction_hash = token_proxy.approve(address, allow_funds)
    assert is_tx_hash_bytes(transaction_hash)
    assert allow_funds == token_proxy.proxy.functions.allowance(
        deploy_client.address, address
    ).call(block_identifier=BLOCK_ID_LATEST)
    other_token_proxy.transfer(deploy_client.address, transfer_funds)
    assert token_proxy.balance_of(address) == 0
