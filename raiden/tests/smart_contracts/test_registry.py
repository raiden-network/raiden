# -*- coding: utf8 -*-
import pytest

from ethereum import slogging
from ethereum.tester import TransactionFailed

from raiden.utils import sha3

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def test_registry(state, registry, events):
    asset_address1 = sha3('asset')[:20]
    asset_address2 = sha3('address')[:20]
    unregistered_address = sha3('mainz')[:20]

    contract_address1 = registry.addAsset(asset_address1)
    contract_address2 = registry.addAsset(asset_address2)

    with pytest.raises(TransactionFailed):
        registry.addAsset(asset_address1)

    channel_manager_address = registry.channelManagerByAsset(asset_address1)
    assert channel_manager_address == contract_address1

    with pytest.raises(TransactionFailed):
        registry.channelManagerByAsset(unregistered_address)

    addresses = registry.assetAddresses()

    assert len(addresses) == 2
    assert addresses[0] == asset_address1.encode('hex')
    assert addresses[1] == asset_address2.encode('hex')

    assert len(events) == 2

    assert events[0]['_event_type'] == 'AssetAdded'
    assert events[0]['assetAddress'] == asset_address1.encode('hex')
    assert events[0]['channelManagerAddress'] == contract_address1

    assert events[1]['_event_type'] == 'AssetAdded'
    assert events[1]['assetAddress'] == asset_address2.encode('hex')
    assert events[1]['channelManagerAddress'] == contract_address2
