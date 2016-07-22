# -*- coding: utf8 -*-
import pytest

import gevent
from ethereum import tester
from ethereum.slogging import configure

from raiden.network.discovery import ContractDiscovery
from raiden.blockchain.abi import get_contract_path

configure(':DEBUG')


def test_endpointregistry():
    registry_contract_path = get_contract_path('EndpointRegistry.sol')
    events = []
    state = tester.state()
    assert state.block.number < 1150000
    state.block.number = 1158001
    assert state.block.number > 1150000
    sender = tester.a0.encode('hex')
    registry_contract = state.abi_contract(
        None,
        path=registry_contract_path,
        language='solidity',
        log_listener=events.append,
    )
    sender = tester.a0.encode('hex')
    registry_contract.registerEndpoint('127.0.0.1:4001')
    assert registry_contract.findAddressByEndpoint('127.0.0.1:4001') == sender
    assert registry_contract.findEndpointByAddress(sender) == '127.0.0.1:4001'
    registry_contract.updateEndpoint('192.168.0.1:4002')
    assert registry_contract.findAddressByEndpoint('192.168.0.1:4002') == sender
    assert registry_contract.findEndpointByAddress(sender) == '192.168.0.1:4002'
    assert len(events) == 2
    assert events[0]['_event_type'] == 'AddressRegistered'
    assert events[1]['_event_type'] == 'AddressUpdated'


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('poll_timeout', [50])
def test_discovery_contract(discovery_blockchain):
    contract_discovery_instance, address = discovery_blockchain
    assert isinstance(contract_discovery_instance, ContractDiscovery)
    contract_discovery_instance.register_endpoint('127.0.0.1', '4001')
    gevent.sleep(30)  # FIXME: this should not be necessary!
    assert contract_discovery_instance.find_address('127.0.0.1', '4001') == address.encode('hex')
