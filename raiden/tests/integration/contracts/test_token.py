from eth_utils import to_canonical_address, to_checksum_address

from raiden.network.proxies import Token
from raiden.network.rpc.client import JSONRPCClient
from raiden.utils import privatekey_to_address


def test_token(
        deploy_client,
        token_proxy,
        private_keys,
        web3,
        contract_manager,
):
    privkey = private_keys[1]
    address = privatekey_to_address(privkey)
    address = to_canonical_address(address)
    other_client = JSONRPCClient(web3, privkey)
    other_token_proxy = Token(
        jsonrpc_client=other_client,
        token_address=to_canonical_address(token_proxy.proxy.contract.address),
        contract_manager=contract_manager,
    )

    # send some funds from deployer to generated address
    transfer_funds = 100
    token_proxy.transfer(address, transfer_funds, 'latest')
    assert transfer_funds == token_proxy.balance_of(address)
    allow_funds = 100
    token_proxy.approve(address, allow_funds, 'latest')
    assert allow_funds == token_proxy.proxy.contract.functions.allowance(
        to_checksum_address(deploy_client.address),
        to_checksum_address(address),
    ).call(block_identifier='latest')
    other_token_proxy.transfer(deploy_client.address, transfer_funds, 'latest')
    assert token_proxy.balance_of(address) == 0
