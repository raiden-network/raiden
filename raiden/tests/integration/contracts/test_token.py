from raiden.utils import privatekey_to_address
from eth_utils import to_canonical_address, to_checksum_address
from raiden.network.proxies import Token
from raiden.network.rpc.client import JSONRPCClient


def test_token(
    deploy_client,
    token_proxy,
    private_keys,
    blockchain_rpc_ports,
    web3,
):
    privkey = private_keys[1]
    address = privatekey_to_address(privkey)
    address = to_canonical_address(address)
    other_client = JSONRPCClient(
        '0.0.0.0',
        blockchain_rpc_ports[0],
        privkey,
        web3=web3,
    )
    other_token_proxy = Token(
        other_client,
        to_canonical_address(token_proxy.proxy.contract.address),
    )

    # send some funds from deployer to generated address
    transfer_funds = 100
    token_proxy.transfer(address, transfer_funds)
    assert transfer_funds == token_proxy.balance_of(address)
    allow_funds = 100
    token_proxy.approve(address, allow_funds)
    assert allow_funds == token_proxy.proxy.contract.functions.allowance(
        to_checksum_address(deploy_client.sender),
        to_checksum_address(address),
    ).call()
    other_token_proxy.transfer(deploy_client.sender, transfer_funds)
    assert token_proxy.balance_of(address) == 0
