# -*- coding: utf-8 -*-
import pytest

from ethereum import slogging
from ethereum.tools import tester

from raiden.tests.fixtures.tester import tester_token_address
from raiden.utils import sha3, address_encoder, event_decoder

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def test_registry(tester_registry, tester_events, private_keys, tester_chain):
    privatekey0 = tester.k0

    token_address1 = tester_token_address(private_keys, 100, tester_chain, 0)
    token_address2 = tester_token_address(private_keys, 100, tester_chain, 1)
    unregistered_address = tester_token_address(private_keys, 100, tester_chain, 2)

    tester_chain.head_state.log_listeners.append(tester_events.append)

    contract_address1 = tester_registry.addToken(token_address1, sender=privatekey0)
    channel_manager_address1 = tester_registry.channelManagerByToken(
        token_address1,
        sender=privatekey0,
    )
    assert channel_manager_address1 == contract_address1

    with pytest.raises(tester.TransactionFailed):
        tester_registry.addToken(token_address1, sender=privatekey0)

    contract_address2 = tester_registry.addToken(token_address2, sender=privatekey0)
    channel_manager_address2 = tester_registry.channelManagerByToken(
        token_address2,
        sender=privatekey0,
    )
    assert channel_manager_address2 == contract_address2

    with pytest.raises(tester.TransactionFailed):
        tester_registry.channelManagerByToken(
            unregistered_address,
            sender=privatekey0,
        )

    addresses = tester_registry.tokenAddresses(sender=privatekey0)

    assert len(addresses) == 2
    assert addresses[0] == address_encoder(token_address1)
    assert addresses[1] == address_encoder(token_address2)

    assert len(tester_events) == 2

    event0 = event_decoder(tester_events[0], tester_registry.translator)
    event1 = event_decoder(tester_events[1], tester_registry.translator)

    assert event0['_event_type'] == b'TokenAdded'
    assert event0['token_address'] == address_encoder(token_address1)
    assert event0['channel_manager_address'] == contract_address1

    assert event1['_event_type'] == b'TokenAdded'
    assert event1['token_address'] == address_encoder(token_address2)
    assert event1['channel_manager_address'] == contract_address2


def test_registry_reject_empty_address(tester_registry, tester_events, private_keys, tester_chain):
    privatekey0 = tester.k0

    with pytest.raises(Exception):
        tester_registry.addToken('', sender=privatekey0)


def test_registry_nonexistent_token(tester_registry, tester_events):
    privatekey0 = tester.k0

    fake_token_address = sha3(b'token')[:20]
    with pytest.raises(tester.TransactionFailed):
        tester_registry.addToken(fake_token_address, sender=privatekey0)


def test_all_contracts_same_version(
        tester_registry,
        tester_channelmanager,
        tester_nettingcontracts,
        endpoint_discovery_services):
    """ Test that all contracts in the repository have the same version"""
    privatekey0 = tester.k0

    registry_version = tester_registry.contract_version(sender=privatekey0)
    channelmanager_version = tester_channelmanager.contract_version(sender=privatekey0)
    channel_version = tester_nettingcontracts[0][2].contract_version(sender=privatekey0)

    endpointregistry_version = endpoint_discovery_services[0].version()

    assert registry_version == channelmanager_version == channel_version
    assert channel_version == endpointregistry_version
