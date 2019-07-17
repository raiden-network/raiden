import pytest
from eth_utils import decode_hex, to_checksum_address
from web3.exceptions import BadFunctionCallOutput

from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract


def test_call_invalid_selector(deploy_client):
    """ A JSON RPC call to a valid address but with an invalid selector returns
    the empty string.
    """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")
    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    selector = decode_hex(contract_proxy.encode_function_call("ret", args=None))
    next_byte = chr(selector[0] + 1).encode()
    wrong_selector = next_byte + selector[1:]
    call = deploy_client.web3.eth.call
    data = {
        "from": to_checksum_address(deploy_client.address),
        "to": to_checksum_address(address),
        "data": wrong_selector,
    }
    assert call(data) == b""


def test_call_inexisting_address(deploy_client):
    """ A JSON RPC call to an inexisting address returns the empty string. """

    inexisting_address = b"\x01\x02\x03\x04\x05" * 4

    assert len(deploy_client.web3.eth.getCode(to_checksum_address(inexisting_address))) == 0
    transaction = {
        "from": to_checksum_address(deploy_client.address),
        "to": to_checksum_address(inexisting_address),
        "data": b"",
        "value": 0,
    }
    assert deploy_client.web3.eth.call(transaction) == b""


def test_call_with_a_block_number_before_smart_contract_deployed(deploy_client):
    """ A JSON RPC call using a block number where the smart contract was not
    yet deployed should raise.
    """
    contract_proxy, receipt = deploy_rpc_test_contract(deploy_client, "RpcTest")

    deploy_block = receipt["blockNumber"]
    assert contract_proxy.contract.functions.ret().call(block_identifier=deploy_block) == 1

    with pytest.raises(BadFunctionCallOutput):
        contract_proxy.contract.functions.ret().call(block_identifier=deploy_block - 1)


def test_call_which_returns_a_string_before_smart_contract_deployed(deploy_client):
    """ A JSON RPC call using a block number where the smart contract was not
    yet deployed should raise, even if the ABI of the function returns an empty
    string.
    """
    contract_proxy, receipt = deploy_rpc_test_contract(deploy_client, "RpcTest")

    deploy_block = receipt["blockNumber"]
    assert contract_proxy.contract.functions.ret_str().call(block_identifier=deploy_block) == ""

    with pytest.raises(BadFunctionCallOutput):
        contract_proxy.contract.functions.ret_str().call(block_identifier=deploy_block - 1)


def test_call_works_with_blockhash(deploy_client):
    """ A JSON RPC call works with a block number or blockhash. """
    contract_proxy, receipt = deploy_rpc_test_contract(deploy_client, "RpcTest")

    deploy_blockhash = receipt["blockHash"]
    assert contract_proxy.contract.functions.ret().call(block_identifier=deploy_blockhash) == 1

    deploy_block = receipt["blockNumber"]
    assert contract_proxy.contract.functions.ret().call(block_identifier=deploy_block) == 1


def test_call_throws(deploy_client):
    """ A JSON RPC call to a function that throws/gets reverted returns the empty string. """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    call = contract_proxy.contract.functions.fail_assert().call
    assert call() == []

    call = contract_proxy.contract.functions.fail_require().call
    assert call() == []
