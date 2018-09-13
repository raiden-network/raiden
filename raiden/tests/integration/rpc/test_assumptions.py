import os

import pytest
from eth_utils import decode_hex, to_checksum_address
from pkg_resources import DistributionNotFound

from raiden.exceptions import ReplacementTransactionUnderpriced, TransactionAlreadyPending
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils.solc import compile_files_cwd

try:
    from evm.exceptions import ValidationError
except (ModuleNotFoundError, DistributionNotFound):
    class ValidationError(Exception):
        pass

try:
    from eth_tester.exceptions import TransactionFailed
except (ModuleNotFoundError, DistributionNotFound):
    class TransactionFailed(Exception):
        pass

# pylint: disable=unused-argument,protected-access


def make_fixed_gas_price_strategy(gas_price):
    def fixed_gas_price_strategy(_web3, _transaction_params):
        return gas_price

    return fixed_gas_price_strategy


def make_decreasing_gas_price_strategy(gas_price):
    # this is a really hacky way to create decreasing numbers
    def increasing_gas_price_strategy(web3, _transaction_params):
        old_counter = getattr(web3, 'counter', gas_price)
        web3.counter = old_counter - 1
        return old_counter

    return increasing_gas_price_strategy


def deploy_rpc_test_contract(deploy_client):
    here = os.path.dirname(os.path.relpath(__file__))
    contract_path = os.path.join(here, 'RpcTest.sol')
    contracts = compile_files_cwd([contract_path])

    contract_proxy = deploy_client.deploy_solidity_contract(
        'RpcTest',
        contracts,
        libraries=dict(),
        constructor_parameters=None,
        contract_path=contract_path,
    )

    return contract_proxy


def get_list_of_block_numbers(item):
    """ Creates a list of block numbers of the given list/single event"""
    if isinstance(item, list):
        return [element['blockNumber'] for element in item]

    if isinstance(item, dict):
        block_number = item['blockNumber']
        return [block_number]

    return list()


def test_call_invalid_selector(blockchain_type, deploy_client):
    """ A JSON RPC call to a valid address but with an invalid selector returns
    the empty string.
    """
    contract_proxy = deploy_rpc_test_contract(deploy_client)
    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    selector = decode_hex(contract_proxy.encode_function_call('ret', args=None))
    next_byte = chr(selector[0] + 1).encode()
    wrong_selector = next_byte + selector[1:]
    call = deploy_client.web3.eth.call
    data = {
        'from': to_checksum_address(deploy_client.sender),
        'to': to_checksum_address(address),
        'data': wrong_selector,
    }
    if blockchain_type == 'tester':
        with pytest.raises(TransactionFailed):
            call(data)
    else:
        assert call(data) == b''


def test_call_inexisting_address(deploy_client):
    """ A JSON RPC call to an inexisting address returns the empty string. """

    inexisting_address = b'\x01\x02\x03\x04\x05' * 4

    assert len(deploy_client.web3.eth.getCode(to_checksum_address(inexisting_address))) == 0
    transaction = {
        'from': to_checksum_address(deploy_client.sender),
        'to': to_checksum_address(inexisting_address),
        'data': b'',
        'value': 0,
    }
    assert deploy_client.web3.eth.call(transaction) == b''


def test_call_throws(blockchain_type, deploy_client):
    """ A JSON RPC call to a function that throws returns the empty string. """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0
    call = contract_proxy.contract.functions.fail().call
    if blockchain_type == 'tester':
        with pytest.raises(TransactionFailed):
            call()
    else:
        assert call() == []


def test_estimate_gas_fail(deploy_client):
    """ A JSON RPC estimate gas call for a throwing transaction returns None"""
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    assert not contract_proxy.estimate_gas('fail')


def test_duplicated_transaction_same_gas_price_raises(deploy_client):
    """ If the same transaction is sent twice a JSON RPC error is raised. """
    gas_price = 2000000000
    gas_price_strategy = make_fixed_gas_price_strategy(gas_price)
    deploy_client.web3.eth.setGasPriceStrategy(gas_price_strategy)
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    second_client = JSONRPCClient(
        web3=deploy_client.web3,
        privkey=deploy_client.privkey,
    )

    second_proxy = second_client.new_contract_proxy(
        contract_proxy.contract.abi,
        contract_proxy.contract_address,
    )

    gas = contract_proxy.estimate_gas('ret') * 2

    with pytest.raises(TransactionAlreadyPending):
        second_proxy.transact('ret', startgas=gas)
        contract_proxy.transact('ret', startgas=gas)


def test_duplicated_transaction_different_gas_price_raises(deploy_client):
    """ If the same transaction is sent twice a JSON RPC error is raised. """
    gas_price = 2000000000
    deploy_client.web3.eth.setGasPriceStrategy(make_decreasing_gas_price_strategy(gas_price))
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    second_client = JSONRPCClient(
        web3=deploy_client.web3,
        privkey=deploy_client.privkey,
    )

    second_proxy = second_client.new_contract_proxy(
        contract_proxy.contract.abi,
        contract_proxy.contract_address,
    )

    gas = contract_proxy.estimate_gas('ret') * 2

    with pytest.raises(ReplacementTransactionUnderpriced):
        second_proxy.transact('ret', startgas=gas)
        contract_proxy.transact('ret', startgas=gas)


def test_transact_opcode(deploy_client):
    """ The receipt status field of a transaction that did not throw is 0x1 """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    gas = contract_proxy.estimate_gas('ret') * 2

    transaction = contract_proxy.transact('ret', startgas=gas)
    deploy_client.poll(transaction)

    assert check_transaction_threw(deploy_client, transaction) is None, 'must be empty'


def test_transact_throws_opcode(deploy_client):
    """ The receipt status field of a transaction that threw is 0x0 """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    gas = deploy_client.gaslimit()

    transaction = contract_proxy.transact('fail', startgas=gas)
    deploy_client.poll(transaction)

    assert check_transaction_threw(deploy_client, transaction), 'must not be empty'


def test_transact_opcode_oog(deploy_client):
    """ The receipt status field of a transaction that did NOT throw is 0x0. """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    gas = min(contract_proxy.estimate_gas('loop', 1000) // 2, deploy_client.gaslimit())

    transaction = contract_proxy.transact('loop', 1000, startgas=gas)
    deploy_client.poll(transaction)

    assert check_transaction_threw(deploy_client, transaction), 'must not be empty'


def test_filter_start_block_inclusive(deploy_client):
    """ A filter includes events from the block given in from_block """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    # call the create event function twice and wait for confirmation each time
    gas = contract_proxy.estimate_gas('createEvent', 1) * 2
    transaction_1 = contract_proxy.transact('createEvent', 1, startgas=gas)
    deploy_client.poll(transaction_1)
    transaction_2 = contract_proxy.transact('createEvent', 2, startgas=gas)
    deploy_client.poll(transaction_2)

    result_1 = deploy_client.get_filter_events(contract_proxy.contract_address)
    block_number_events = get_list_of_block_numbers(result_1)
    block_number_event_1 = block_number_events[0]
    block_number_event_2 = block_number_events[1]

    # inclusive from_block should return both events
    result_2 = deploy_client.get_filter_events(
        contract_proxy.contract_address,
        from_block=block_number_event_1,
    )
    assert get_list_of_block_numbers(result_2) == block_number_events

    # a higher from_block must not contain the first event
    result_3 = deploy_client.get_filter_events(
        contract_proxy.contract_address,
        from_block=block_number_event_1 + 1,
    )
    assert get_list_of_block_numbers(result_3) == [block_number_event_2]


def test_filter_end_block_inclusive(deploy_client):
    """ A filter includes events from the block given in from_block
    until and including end_block. """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    # call the create event function twice and wait for confirmation each time
    gas = contract_proxy.estimate_gas('createEvent', 1) * 2
    transaction_1 = contract_proxy.transact('createEvent', 1, startgas=gas)
    deploy_client.poll(transaction_1)
    transaction_2 = contract_proxy.transact('createEvent', 2, startgas=gas)
    deploy_client.poll(transaction_2)

    result_1 = deploy_client.get_filter_events(contract_proxy.contract_address)
    block_number_events = get_list_of_block_numbers(result_1)
    block_number_event_1 = block_number_events[0]
    block_number_event_2 = block_number_events[1]

    # inclusive to_block should return first event
    result_2 = deploy_client.get_filter_events(
        contract_proxy.contract_address,
        to_block=block_number_event_1,
    )
    assert get_list_of_block_numbers(result_2) == [block_number_event_1]

    # this should include the second event
    result_3 = deploy_client.get_filter_events(
        contract_proxy.contract_address,
        to_block=block_number_event_2,
    )
    assert get_list_of_block_numbers(result_3) == block_number_events
