# -*- coding: utf-8 -*-
import pytest

from ethereum import slogging
from ethereum import tester

from raiden.utils import sha3

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def test_registry(tester_registry, tester_events):
    privatekey0 = tester.DEFAULT_KEY

    token_address1 = sha3('token')[:20]
    token_address2 = sha3('address')[:20]
    unregistered_address = sha3('mainz')[:20]

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
    assert addresses[0] == token_address1.encode('hex')
    assert addresses[1] == token_address2.encode('hex')

    assert len(tester_events) == 2

    assert tester_events[0]['_event_type'] == 'TokenAdded'
    assert tester_events[0]['token_address'] == token_address1.encode('hex')
    assert tester_events[0]['channel_manager_address'] == contract_address1

    assert tester_events[1]['_event_type'] == 'TokenAdded'
    assert tester_events[1]['token_address'] == token_address2.encode('hex')
    assert tester_events[1]['channel_manager_address'] == contract_address2
