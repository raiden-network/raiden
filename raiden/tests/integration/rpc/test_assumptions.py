# -*- coding: utf-8 -*-
from __future__ import division

import os

import pytest
from ethereum import _solidity

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


@pytest.mark.parametrize('blockchain_type', ['geth'])
def test_call_inexisting_address(deploy_client, blockchain_backend):
    """ A JSON RPC call to an inexisting address returns the empty string. """

    inexisting_address = '\x01\x02\x03\x04\x05' * 4

    assert deploy_client.eth_getCode(inexisting_address) == '0x'
    assert deploy_client.eth_call(sender=deploy_client.sender, to=inexisting_address) == ''


@pytest.mark.parametrize('blockchain_type', ['geth'])
def test_call_invalid_selector(deploy_client, blockchain_backend):
    """ A JSON RPC call to a valid address but with an invalid selector returns
    the empty string.
    """
    contract_proxy = deploy_rpc_test_contract(deploy_client)
    address = contract_proxy.address
    assert deploy_client.eth_getCode(address) != '0x'

    selector = contract_proxy.translator.encode_function_call('ret', args=[])
    next_byte = chr(ord(selector[0]) + 1)
    wrong_selector = next_byte + selector[1:]
    result = deploy_client.eth_call(
        sender=deploy_client.sender,
        to=address,
        data=wrong_selector,
    )
    assert result == ''


@pytest.mark.parametrize('blockchain_type', ['geth'])
def test_call_throws(deploy_client, blockchain_backend):
    """ A JSON RPC call to a function that throws returns the empty string. """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.address
    assert deploy_client.eth_getCode(address) != '0x'

    assert contract_proxy.fail.call() == ''


@pytest.mark.parametrize('blockchain_type', ['geth'])
def test_transact_opcode(deploy_client, blockchain_backend):
    """ The receipt status field of a transaction that did not throw is 0x1 """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.address
    assert deploy_client.eth_getCode(address) != '0x'

    gas = contract_proxy.ret.estimate_gas() * 2

    transaction_hex = contract_proxy.ret.transact(startgas=gas)
    transaction = transaction_hex.decode('hex')

    deploy_client.poll(transaction)

    assert check_transaction_threw(deploy_client, transaction_hex) is None, 'must be empty'


@pytest.mark.parametrize('blockchain_type', ['geth'])
def test_transact_throws_opcode(deploy_client, blockchain_backend):
    """ The receipt status field of a transaction that threw is 0x0 """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.address
    assert deploy_client.eth_getCode(address) != '0x'

    gas = min(contract_proxy.fail.estimate_gas(), deploy_client.gaslimit())
    transaction_hex = contract_proxy.fail.transact(startgas=gas)
    transaction = transaction_hex.decode('hex')

    deploy_client.poll(transaction)

    assert check_transaction_threw(deploy_client, transaction_hex), 'must not be empty'


@pytest.mark.parametrize('blockchain_type', ['geth'])
def test_transact_opcode_oog(deploy_client, blockchain_backend):
    """ The receipt status field of a transaction that did NOT throw is 0x0. """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    address = contract_proxy.address
    assert deploy_client.eth_getCode(address) != '0x'

    gas = min(contract_proxy.loop.estimate_gas(1000) // 2, deploy_client.gaslimit)
    transaction_hex = contract_proxy.loop.transact(1000, startgas=gas)
    transaction = transaction_hex.decode('hex')

    deploy_client.poll(transaction)

    assert check_transaction_threw(deploy_client, transaction_hex), 'must not be empty'


def get_list_of_block_numbers(item):
    """ Creates a list of block numbers of the given list/single event"""
    if isinstance(item, list):
        return [element['block_number'] for element in item]
    elif isinstance(item, dict):
        block_number = item['block_number']
        return [block_number]
    else:
        return []


@pytest.mark.parametrize('blockchain_type', ['geth'])
def test_filter_start_block_inclusive(deploy_client, blockchain_backend):
    """ A filter includes events from the block given in from_block """
    contract_proxy = deploy_rpc_test_contract(deploy_client)

    # call the create event function twice and wait for confirmtion each time
    gas = contract_proxy.createEvent.estimate_gas() * 2
    transaction_hex_1 = contract_proxy.createEvent.transact(1, startgas=gas)
    deploy_client.poll(transaction_hex_1.decode('hex'))
    transaction_hex_2 = contract_proxy.createEvent.transact(2, startgas=gas)
    deploy_client.poll(transaction_hex_2.decode('hex'))

    # create a new filter in the node
    new_filter(deploy_client, contract_proxy.address, None)

    result_1 = get_filter_events(deploy_client, contract_proxy.address, None)
    block_number_events = get_list_of_block_numbers(result_1)
    block_number_event_1 = block_number_events[0]
    block_number_event_2 = block_number_events[1]

    # inclusive from_block should return both events
    result_2 = get_filter_events(deploy_client,
                                 contract_proxy.address,
                                 None,
                                 from_block=block_number_event_1)
    assert get_list_of_block_numbers(result_2) == block_number_events

    # a higher from_block must not contain the first event
    result_3 = get_filter_events(deploy_client,
                                 contract_proxy.address,
                                 None,
                                 from_block=block_number_event_1 + 1)
    assert get_list_of_block_numbers(result_3) == [block_number_event_2]
