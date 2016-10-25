# -*- coding: utf-8 -*-
from ethereum import tester
from raiden.utils import get_contract_path


def test_endpointregistry(tester_state, tester_events):
    account0 = tester.DEFAULT_ACCOUNT
    sender = account0.encode('hex')

    endpointregistry_path = get_contract_path('EndpointRegistry.sol')
    registry_contract = tester_state.abi_contract(
        None,
        path=endpointregistry_path,
        language='solidity',
        log_listener=tester_events.append,
    )

    registry_contract.registerEndpoint('127.0.0.1:4001')
    assert registry_contract.findAddressByEndpoint('127.0.0.1:4001') == sender
    assert registry_contract.findEndpointByAddress(sender) == '127.0.0.1:4001'

    registry_contract.registerEndpoint('192.168.0.1:4002')
    assert registry_contract.findAddressByEndpoint('192.168.0.1:4002') == sender
    assert registry_contract.findEndpointByAddress(sender) == '192.168.0.1:4002'

    assert len(tester_events) == 2
    assert tester_events[0]['_event_type'] == 'AddressRegistered'
    assert tester_events[1]['_event_type'] == 'AddressRegistered'
