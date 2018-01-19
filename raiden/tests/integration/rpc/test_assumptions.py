# -*- coding: utf-8 -*-
from binascii import unhexlify
import os

from ethereum.tools import _solidity

from raiden.network.rpc.filters import new_filter, get_filter_events
from raiden.network.rpc.transactions import check_transaction_threw

# pylint: disable=unused-argument,protected-access


def deploy_rpc_test_contract(deploy_client):
    here = os.path.dirname(os.path.relpath(__file__))
    contract_path = os.path.join(here, 'RpcTest.sol')
    contracts = _solidity.compile_file(contract_path, libraries=dict())

    contract_proxy = deploy_client.deploy_solidity_contract(
        deploy_client.sender,
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
        return [element['block_number'] for element in item]

    if isinstance(item, dict):
        block_number = item['block_number']
        return [block_number]

    return list()


def test_call_inexisting_address(deploy_client, blockchain_backend):
    """ A JSON RPC call to an inexisting address returns the empty string. """

    inexisting_address = b'\x01\x02\x03\x04\x05' * 4

    assert len(deploy_client.eth_getCode(inexisting_address)) == 0
    assert deploy_client.eth_call(sender=deploy_client.sender, to=inexisting_address) == b''


def test_call_invalid_selector(deploy_client, blockchain_backend):
    """ A JSON RPC call to a valid address but with an invalid selector returns
    the empty string.
    """
    contract_proxy = deploy_rpc_test_contract(deploy_client)
    address = contract_proxy.contract_address
    assert len(deploy_client.eth_getCode(address)) > 0

    selector = contract_proxy.translator.encode_function_call('ret', args=[])
    next_byte = chr(selector[0] + 1).encode()
    wrong_selector = next_byte + selector[1:]
    result = deploy_client.eth_call(
        sender=deploy_client.sender,
        to=address,
        data=wrong_selector,
    )
    assert result == b''


def test_call_throws(deploy_client, blockchain_backend):
    """ A JSON RPC call to a function that throws returns the empty string. """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.contract_address
    assert len(deploy_client.eth_getCode(address)) > 0

    assert contract_proxy.call('fail') == b''


def test_transact_opcode(deploy_client, blockchain_backend):
    """ The receipt status field of a transaction that did not throw is 0x1 """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.contract_address
    assert len(deploy_client.eth_getCode(address)) > 0

    gas = contract_proxy.estimate_gas('ret') * 2

    transaction_hex = contract_proxy.transact('ret', startgas=gas)
    transaction = unhexlify(transaction_hex)

    deploy_client.poll(transaction)

    assert check_transaction_threw(deploy_client, transaction_hex) is None, 'must be empty'


def test_transact_throws_opcode(deploy_client, blockchain_backend):
    """ The receipt status field of a transaction that threw is 0x0 """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.contract_address
    assert len(deploy_client.eth_getCode(address)) > 0

    gas = min(
        contract_proxy.estimate_gas('fail'),
        deploy_client.gaslimit(),
    )

    transaction_hex = contract_proxy.transact('fail', startgas=gas)
    transaction = unhexlify(transaction_hex)

    deploy_client.poll(transaction)

    assert check_transaction_threw(deploy_client, transaction_hex), 'must not be empty'


def test_transact_opcode_oog(deploy_client, blockchain_backend):
    """ The receipt status field of a transaction that did NOT throw is 0x0. """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.contract_address
    assert len(deploy_client.eth_getCode(address)) > 0

    gas = min(contract_proxy.estimate_gas('loop', 1000) // 2, deploy_client.gaslimit())
    transaction_hex = contract_proxy.transact('loop', 1000, startgas=gas)
    transaction = unhexlify(transaction_hex)

    deploy_client.poll(transaction)

    assert check_transaction_threw(deploy_client, transaction_hex), 'must not be empty'


def test_filter_start_block_inclusive(deploy_client, blockchain_backend):
    """ A filter includes events from the block given in from_block """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    # call the create event function twice and wait for confirmation each time
    gas = contract_proxy.estimate_gas('createEvent') * 2
    transaction_hex_1 = contract_proxy.transact('createEvent', 1, startgas=gas)
    deploy_client.poll(unhexlify(transaction_hex_1))
    transaction_hex_2 = contract_proxy.transact('createEvent', 2, startgas=gas)
    deploy_client.poll(unhexlify(transaction_hex_2))

    # create a new filter in the node
    new_filter(deploy_client, contract_proxy.contract_address, None)

    result_1 = get_filter_events(deploy_client, contract_proxy.contract_address, None)
    block_number_events = get_list_of_block_numbers(result_1)
    block_number_event_1 = block_number_events[0]
    block_number_event_2 = block_number_events[1]

    # inclusive from_block should return both events
    result_2 = get_filter_events(
        deploy_client,
        contract_proxy.contract_address,
        None,
        from_block=block_number_event_1,
    )
    assert get_list_of_block_numbers(result_2) == block_number_events

    # a higher from_block must not contain the first event
    result_3 = get_filter_events(
        deploy_client,
        contract_proxy.contract_address,
        None,
        from_block=block_number_event_1 + 1,
    )
    assert get_list_of_block_numbers(result_3) == [block_number_event_2]
