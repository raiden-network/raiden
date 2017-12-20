# -*- coding: utf-8 -*-
from ethereum.tools import tester, _solidity
from raiden.utils import get_contract_path, address_encoder, event_decoder


def test_endpointregistry(tester_chain, tester_events):
    account0 = tester.a0
    sender = address_encoder(account0)

    endpointregistry_path = get_contract_path('EndpointRegistry.sol')

    endpointregistry_compiled = _solidity.compile_contract(
        endpointregistry_path,
        "EndpointRegistry"
    )
    tester_chain.head_state.log_listeners.append(tester_events.append)
    endpointregistry_address = tester_chain.contract(
        endpointregistry_compiled['bin'],
        language='evm'
    )
    endpoint_registry = tester.ABIContract(
        tester_chain,
        endpointregistry_compiled['abi'],
        endpointregistry_address
    )

    endpoint_registry.registerEndpoint('127.0.0.1:4001')
    assert endpoint_registry.findAddressByEndpoint('127.0.0.1:4001') == sender
    assert endpoint_registry.findEndpointByAddress(sender) == b'127.0.0.1:4001'

    endpoint_registry.registerEndpoint('192.168.0.1:4002')
    assert endpoint_registry.findAddressByEndpoint('192.168.0.1:4002') == sender
    assert endpoint_registry.findEndpointByAddress(sender) == b'192.168.0.1:4002'

    assert len(tester_events) == 2

    event0 = event_decoder(tester_events[0], endpoint_registry.translator)
    event1 = event_decoder(tester_events[1], endpoint_registry.translator)
    assert event0['_event_type'] == b'AddressRegistered'
    assert event1['_event_type'] == b'AddressRegistered'
