# -*- coding: utf8 -*-
import pytest

from ethereum import tester
from ethereum import slogging
from ethereum.tester import ABIContract, TransactionFailed

from raiden.messages import Lock, DirectTransfer
from raiden.mtree import merkleroot
from raiden.utils import privtoaddr, sha3

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def test_registry(state, registry, events):

    contract_address1 = registry.addAsset(sha3('asset')[:20])
    contract_address2 = registry.addAsset(sha3('address')[:20])
    # if address already exists, throw
    with pytest.raises(TransactionFailed):
        registry.addAsset(sha3('asset')[:20])

    cmc = registry.channelManagerByAsset(sha3('asset')[:20])
    assert cmc == contract_address1
    # if address does not exist, throw
    with pytest.raises(TransactionFailed):
        registry.channelManagerByAsset(sha3('mainz')[:20])

    adrs = registry.assetAddresses()
    assert len(adrs) == 2
    assert adrs[0] == sha3('asset')[:20].encode('hex')
    assert adrs[1] == sha3('address')[:20].encode('hex')
    assert len(events) == 2
    assert events[0]['_event_type'] == 'AssetAdded'
    assert events[0]['assetAddress'] == contract_address1
    assert events[1]['_event_type'] == 'AssetAdded'
    assert events[1]['assetAddress'] == contract_address2
