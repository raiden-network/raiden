from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract, get_list_of_block_numbers
from raiden.utils.smart_contracts import safe_gas_limit


def test_filter_start_block_inclusive(deploy_client: JSONRPCClient) -> None:
    """ A filter includes events from the block given in from_block """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    check_block = deploy_client.get_checking_block()
    # call the create event function twice and wait for confirmation each time
    startgas = deploy_client.estimate_gas(contract_proxy, check_block, "createEvent", 1)
    assert startgas
    startgas = safe_gas_limit(startgas)
    transaction_1 = deploy_client.transact(contract_proxy, "createEvent", startgas, 1)
    deploy_client.poll_transaction(transaction_1)
    transaction_2 = deploy_client.transact(contract_proxy, "createEvent", startgas, 2)
    deploy_client.poll_transaction(transaction_2)

    result_1 = deploy_client.get_filter_events(contract_proxy.address)
    block_number_events = get_list_of_block_numbers(result_1)
    block_number_event_1 = block_number_events[0]
    block_number_event_2 = block_number_events[1]

    # inclusive from_block should return both events
    result_2 = deploy_client.get_filter_events(
        contract_proxy.address, from_block=block_number_event_1
    )
    assert get_list_of_block_numbers(result_2) == block_number_events

    # a higher from_block must not contain the first event
    result_3 = deploy_client.get_filter_events(
        contract_proxy.address, from_block=block_number_event_1 + 1
    )
    assert get_list_of_block_numbers(result_3) == [block_number_event_2]


def test_filter_end_block_inclusive(deploy_client: JSONRPCClient) -> None:
    """ A filter includes events from the block given in from_block
    until and including end_block. """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    check_block = deploy_client.get_checking_block()
    # call the create event function twice and wait for confirmation each time
    startgas = deploy_client.estimate_gas(contract_proxy, check_block, "createEvent", 1)
    assert startgas
    startgas = safe_gas_limit(startgas)
    transaction_1 = deploy_client.transact(contract_proxy, "createEvent", startgas, 1)
    deploy_client.poll_transaction(transaction_1)
    transaction_2 = deploy_client.transact(contract_proxy, "createEvent", startgas, 2)
    deploy_client.poll_transaction(transaction_2)

    result_1 = deploy_client.get_filter_events(contract_proxy.address)
    block_number_events = get_list_of_block_numbers(result_1)
    block_number_event_1 = block_number_events[0]
    block_number_event_2 = block_number_events[1]

    # inclusive to_block should return first event
    result_2 = deploy_client.get_filter_events(
        contract_proxy.address, to_block=block_number_event_1
    )
    assert get_list_of_block_numbers(result_2) == [block_number_event_1]

    # this should include the second event
    result_3 = deploy_client.get_filter_events(
        contract_proxy.address, to_block=block_number_event_2
    )
    assert get_list_of_block_numbers(result_3) == block_number_events
