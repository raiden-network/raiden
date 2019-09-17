import pytest

from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract


def test_transact_is_rejected_if_the_nonce_is_too_low(deploy_client: JSONRPCClient) -> None:
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    # Create a new instance of the JSONRPCClient, this will store the current available nonce
    client_invalid_nonce = JSONRPCClient(deploy_client.web3, deploy_client.privkey)

    check_block = deploy_client.get_checking_block()
    txhash = contract_proxy.transact("ret", contract_proxy.estimate_gas(check_block, "ret"))

    # Wait for the transaction to be mined (cuncurrent transactions are tested
    # by test_local_transaction_with_zero_gasprice_is_mined)
    deploy_client.poll(txhash)

    with pytest.raises(ValueError):
        client_invalid_nonce.new_contract_proxy(
            abi=contract_proxy.contract.abi, contract_address=contract_proxy.contract_address
        ).transact("ret", contract_proxy.estimate_gas(check_block, "ret"))
