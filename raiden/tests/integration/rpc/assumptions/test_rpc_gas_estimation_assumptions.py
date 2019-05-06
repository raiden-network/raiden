from eth_utils import to_checksum_address

from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract

SSTORE_COST = 20000


def test_estimate_gas_fail(deploy_client):
    """ A JSON RPC estimate gas call for a throwing transaction returns None"""
    contract_proxy = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    check_block = deploy_client.get_checking_block()
    assert not contract_proxy.estimate_gas(check_block, "fail")


def test_estimate_gas_fails_if_startgas_is_higher_than_blockgaslimit(
    deploy_client, skip_if_not_geth  # pylint: disable=unused-argument
):
    """ Gas estimation fails if the transaction execution requires more gas
    then the block's gas limit.
    """
    contract_proxy = deploy_rpc_test_contract(deploy_client, "RpcWithStorageTest")

    latest_block_hash = deploy_client.blockhash_from_blocknumber("latest")
    current_gas_limit = deploy_client.get_block(latest_block_hash)["gasLimit"]

    # This number of iterations is an over estimation to accomodate for races,
    # this cannot be significantly large because on parity it is a blocking
    # call.
    number_iterations = current_gas_limit // SSTORE_COST

    # This race condition cannot be fixed because geth does not support
    # block_identifier for eth_estimateGas. The test should not be flaky
    # because number_iterations is order of magnitudes larger then it needs to
    # be
    block_identifier = None

    startgas = contract_proxy.estimate_gas(block_identifier, "waste_storage", number_iterations)
    assert startgas is None, "estimate_gas must return empty if sending the transaction would fail"
