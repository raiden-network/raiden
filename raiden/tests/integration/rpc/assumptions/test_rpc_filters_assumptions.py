from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract, get_list_of_block_numbers
from raiden.utils import safe_gas_limit


def test_filter_start_block_inclusive(deploy_client):
    """ A filter includes events from the block given in from_block """
    contract_proxy = deploy_rpc_test_contract(deploy_client, "RpcTest")

    check_block = deploy_client.get_checking_block()
    # call the create event function twice and wait for confirmation each time
    startgas = safe_gas_limit(contract_proxy.estimate_gas(check_block, "createEvent", 1))
    transaction_1 = contract_proxy.transact("createEvent", startgas, 1)
    deploy_client.poll(transaction_1)
    transaction_2 = contract_proxy.transact("createEvent", startgas, 2)
    deploy_client.poll(transaction_2)

    result_1 = deploy_client.get_filter_events(contract_proxy.contract_address)
    block_number_events = get_list_of_block_numbers(result_1)
    block_number_event_1 = block_number_events[0]
    block_number_event_2 = block_number_events[1]

    # inclusive from_block should return both events
    result_2 = deploy_client.get_filter_events(
        contract_proxy.contract_address, from_block=block_number_event_1
    )
    assert get_list_of_block_numbers(result_2) == block_number_events

    # a higher from_block must not contain the first event
    result_3 = deploy_client.get_filter_events(
        contract_proxy.contract_address, from_block=block_number_event_1 + 1
    )
    assert get_list_of_block_numbers(result_3) == [block_number_event_2]


def test_filter_end_block_inclusive(deploy_client):
    """ A filter includes events from the block given in from_block
    until and including end_block. """
    contract_proxy = deploy_rpc_test_contract(deploy_client, "RpcTest")

    check_block = deploy_client.get_checking_block()
    # call the create event function twice and wait for confirmation each time
    startgas = safe_gas_limit(contract_proxy.estimate_gas(check_block, "createEvent", 1))
    transaction_1 = contract_proxy.transact("createEvent", startgas, 1)
    deploy_client.poll(transaction_1)
    transaction_2 = contract_proxy.transact("createEvent", startgas, 2)
    deploy_client.poll(transaction_2)

    result_1 = deploy_client.get_filter_events(contract_proxy.contract_address)
    block_number_events = get_list_of_block_numbers(result_1)
    block_number_event_1 = block_number_events[0]
    block_number_event_2 = block_number_events[1]

    # inclusive to_block should return first event
    result_2 = deploy_client.get_filter_events(
        contract_proxy.contract_address, to_block=block_number_event_1
    )
    assert get_list_of_block_numbers(result_2) == [block_number_event_1]

    # this should include the second event
    result_3 = deploy_client.get_filter_events(
        contract_proxy.contract_address, to_block=block_number_event_2
    )
    assert get_list_of_block_numbers(result_3) == block_number_events
