# -*- coding: utf8 -*-
import pytest

from ethereum import slogging
from ethereum.tester import TransactionFailed

from raiden.utils import sha3

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def test_registry(tester_registry, tester_events):
    asset_address1 = sha3('asset')[:20]
    asset_address2 = sha3('address')[:20]
    unregistered_address = sha3('mainz')[:20]

    contract_address1 = tester_registry.addAsset(asset_address1)
    contract_address2 = tester_registry.addAsset(asset_address2)

    with pytest.raises(TransactionFailed):
        tester_registry.addAsset(asset_address1)

    channel_manager_address = tester_registry.channelManagerByAsset(asset_address1)
    assert channel_manager_address == contract_address1

    with pytest.raises(TransactionFailed):
        tester_registry.channelManagerByAsset(unregistered_address)

    addresses = tester_registry.assetAddresses()

    assert len(addresses) == 2
    assert addresses[0] == asset_address1.encode('hex')
    assert addresses[1] == asset_address2.encode('hex')

    assert len(tester_events) == 2

    assert tester_events[0]['_event_type'] == 'AssetAdded'
    assert tester_events[0]['assetAddress'] == asset_address1.encode('hex')
    assert tester_events[0]['channelManagerAddress'] == contract_address1

    assert tester_events[1]['_event_type'] == 'AssetAdded'
    assert tester_events[1]['assetAddress'] == asset_address2.encode('hex')
    assert tester_events[1]['channelManagerAddress'] == contract_address2
