from eth_utils import to_canonical_address

from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract, get_list_of_block_numbers


def test_filter_start_block_inclusive(deploy_client: JSONRPCClient) -> None:
    """ A filter includes events from the block given in from_block """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    # call the create event function twice and wait for confirmation each time
    estimated_transaction1 = deploy_client.estimate_gas(contract_proxy, "createEvent", {}, 1)
    assert estimated_transaction1
    transaction_1 = deploy_client.transact(estimated_transaction1)
    deploy_client.poll_transaction(transaction_1)

    estimated_transaction2 = deploy_client.estimate_gas(contract_proxy, "createEvent", {}, 1)
    assert estimated_transaction2
    transaction_2 = deploy_client.transact(estimated_transaction2)
    deploy_client.poll_transaction(transaction_2)

    contract_proxy_address = to_canonical_address(contract_proxy.address)

    result_1 = deploy_client.get_filter_events(contract_proxy_address)
    block_number_events = get_list_of_block_numbers(result_1)
    block_number_event_1 = block_number_events[0]
    block_number_event_2 = block_number_events[1]

    # inclusive from_block should return both events
    result_2 = deploy_client.get_filter_events(
        contract_proxy_address, from_block=block_number_event_1
    )
    assert get_list_of_block_numbers(result_2) == block_number_events

    # a higher from_block must not contain the first event
    result_3 = deploy_client.get_filter_events(
        contract_proxy_address, from_block=block_number_event_1 + 1
    )
    assert get_list_of_block_numbers(result_3) == [block_number_event_2]


def test_filter_end_block_inclusive(deploy_client: JSONRPCClient) -> None:
    """A filter includes events from the block given in from_block
    until and including end_block."""
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    # call the create event function twice and wait for confirmation each time
    estimated_transaction1 = deploy_client.estimate_gas(contract_proxy, "createEvent", {}, 1)
    assert estimated_transaction1
    transaction_1 = deploy_client.transact(estimated_transaction1)
    deploy_client.poll_transaction(transaction_1)

    estimated_transaction2 = deploy_client.estimate_gas(contract_proxy, "createEvent", {}, 1)
    assert estimated_transaction2
    transaction_2 = deploy_client.transact(estimated_transaction2)
    deploy_client.poll_transaction(transaction_2)

    contract_proxy_address = to_canonical_address(contract_proxy.address)

    result_1 = deploy_client.get_filter_events(contract_proxy_address)
    block_number_events = get_list_of_block_numbers(result_1)
    block_number_event_1 = block_number_events[0]
    block_number_event_2 = block_number_events[1]

    # inclusive to_block should return first event
    result_2 = deploy_client.get_filter_events(
        contract_proxy_address, to_block=block_number_event_1
    )
    assert get_list_of_block_numbers(result_2) == [block_number_event_1]

    # this should include the second event
    result_3 = deploy_client.get_filter_events(
        contract_proxy_address, to_block=block_number_event_2
    )
    assert get_list_of_block_numbers(result_3) == block_number_events
