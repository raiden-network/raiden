import pytest
from eth_utils import decode_hex
from web3.exceptions import BadFunctionCallOutput

from raiden.network.rpc.client import JSONRPCClient, get_transaction_data
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract


def test_call_invalid_selector(deploy_client: JSONRPCClient) -> None:
    """A JSON RPC call to a valid address but with an invalid selector returns
    the empty string.
    """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")
    address = contract_proxy.address
    assert len(deploy_client.web3.eth.get_code(address)) > 0

    data = decode_hex(get_transaction_data(deploy_client.web3, contract_proxy.abi, "ret", None))
    next_byte = chr(data[0] + 1).encode()
    data_with_wrong_selector = next_byte + data[1:]
    call = deploy_client.web3.eth.call
    transaction = {"from": deploy_client.address, "to": address, "data": data_with_wrong_selector}
    assert call(transaction) == b""


def test_call_inexisting_address(deploy_client: JSONRPCClient) -> None:
    """ A JSON RPC call to an inexisting address returns the empty string. """

    inexisting_address = b"\x01\x02\x03\x04\x05" * 4

    assert len(deploy_client.web3.eth.get_code(inexisting_address)) == 0
    transaction = {
        "from": deploy_client.address,
        "to": inexisting_address,
        "data": b"",
        "value": 0,
    }
    assert deploy_client.web3.eth.call(transaction) == b""


def test_call_with_a_block_number_before_smart_contract_deployed(
    deploy_client: JSONRPCClient,
) -> None:
    """A JSON RPC call using a block number where the smart contract was not
    yet deployed should raise.
    """
    contract_proxy, receipt = deploy_rpc_test_contract(deploy_client, "RpcTest")

    deploy_block = receipt["blockNumber"]
    assert contract_proxy.functions.ret().call(block_identifier=deploy_block) == 1

    with pytest.raises(BadFunctionCallOutput):
        contract_proxy.functions.ret().call(block_identifier=deploy_block - 1)


def test_call_which_returns_a_string_before_smart_contract_deployed(
    deploy_client: JSONRPCClient,
) -> None:
    """A JSON RPC call using a block number where the smart contract was not
    yet deployed should raise, even if the ABI of the function returns an empty
    string.
    """
    contract_proxy, receipt = deploy_rpc_test_contract(deploy_client, "RpcTest")

    deploy_block = receipt["blockNumber"]
    assert contract_proxy.functions.ret_str().call(block_identifier=deploy_block) == ""

    with pytest.raises(BadFunctionCallOutput):
        contract_proxy.functions.ret_str().call(block_identifier=deploy_block - 1)


def test_call_works_with_blockhash(deploy_client: JSONRPCClient) -> None:
    """ A JSON RPC call works with a block number or blockhash. """
    contract_proxy, receipt = deploy_rpc_test_contract(deploy_client, "RpcTest")

    deploy_blockhash = receipt["blockHash"]
    assert contract_proxy.functions.ret().call(block_identifier=deploy_blockhash) == 1

    deploy_block = receipt["blockNumber"]
    assert contract_proxy.functions.ret().call(block_identifier=deploy_block) == 1


def test_call_throws(deploy_client: JSONRPCClient) -> None:
    """ A JSON RPC call to a function that throws/gets reverted returns the empty string. """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.address
    assert len(deploy_client.web3.eth.get_code(address)) > 0

    call = contract_proxy.functions.fail_assert().call
    assert call() == []

    call = contract_proxy.functions.fail_require().call
    assert call() == []
