# -*- coding: utf8 -*-
import random
import string

import pytest
from ethereum import slogging

from raiden.network.rpc.client import BlockChainServiceMock
from raiden.utils import isaddress

slogging.configure(':debug')

LETTERS = string.printable


def make_address():
    return ''.join(random.choice(LETTERS) for _ in range(20))


def test_new_netting_contract():
    # pylint: disable=line-too-long,too-many-statements
    client = BlockChainServiceMock()

    asset_address = make_address()
    peer1_address = make_address()
    peer2_address = make_address()
    peer3_address = make_address()

    contract_address = client.new_channel_manager_contract(asset_address)
    assert isaddress(contract_address)

    # sanity
    assert client.addresses_by_asset(asset_address) == []
    assert client.nettingaddresses_by_asset_participant(
        asset_address,
        peer1_address,
    ) == []
    assert client.nettingaddresses_by_asset_participant(
        asset_address,
        peer2_address
    ) == []
    assert client.nettingaddresses_by_asset_participant(
        asset_address,
        peer3_address
    ) == []

    # create one channel
    netting1_address = client.new_netting_contract(asset_address, peer1_address, peer2_address)

    # check contract state
    assert isaddress(netting1_address)
    assert client.isopen(asset_address, netting1_address) is False
    assert client.partner(asset_address, netting1_address, peer1_address) == peer2_address
    assert client.partner(asset_address, netting1_address, peer2_address) == peer1_address

    # check channels
    assert sorted(client.addresses_by_asset(asset_address)[0]) == sorted([peer1_address, peer2_address])

    assert client.nettingaddresses_by_asset_participant(
        asset_address,
        peer1_address
    ) == [netting1_address]
    assert client.nettingaddresses_by_asset_participant(
        asset_address,
        peer2_address
    ) == [netting1_address]
    assert client.nettingaddresses_by_asset_participant(asset_address, peer3_address) == []

    # cant recreate the existing channel
    with pytest.raises(Exception):
        client.new_netting_contract(asset_address, peer1_address, peer2_address)

    # create other chanel
    netting2_address = client.new_netting_contract(asset_address, peer1_address, peer3_address)

    assert isaddress(netting2_address)
    assert client.isopen(asset_address, netting2_address) is False
    assert client.partner(asset_address, netting2_address, peer1_address) == peer3_address
    assert client.partner(asset_address, netting2_address, peer3_address) == peer1_address

    channel_list = client.addresses_by_asset(asset_address)
    expected_channels = [
        sorted([peer1_address, peer2_address]),
        sorted([peer1_address, peer3_address]),
    ]

    for channel in channel_list:
        assert sorted(channel) in expected_channels

    assert sorted(client.nettingaddresses_by_asset_participant(asset_address, peer1_address)) == sorted([
        netting1_address,
        netting2_address,
    ])
    assert client.nettingaddresses_by_asset_participant(asset_address, peer2_address) == [netting1_address]
    assert client.nettingaddresses_by_asset_participant(asset_address, peer3_address) == [netting2_address]

    client.deposit(asset_address, netting1_address, peer1_address, 100)
    assert client.isopen(asset_address, netting1_address) is False
    assert client.isopen(asset_address, netting2_address) is False

    # with pytest.raises(Exception):
    #    client.deposit(asset_address, netting1_address, peer1_address, 100)

    client.deposit(asset_address, netting2_address, peer1_address, 70)
    assert client.isopen(asset_address, netting1_address) is False
    assert client.isopen(asset_address, netting2_address) is False

    client.deposit(asset_address, netting1_address, peer2_address, 130)
    assert client.isopen(asset_address, netting1_address) is True
    assert client.isopen(asset_address, netting2_address) is False

    # we need to allow the settlement of the channel even if no transfers were
    # made
    peer1_last_sent_transfer = None
    peer2_last_sent_transfer = None

    client.close(
        asset_address,
        netting1_address,
        peer1_address,
        peer1_last_sent_transfer,
        peer2_last_sent_transfer,
    )

    # with pytest.raises(Exception):
    #     client.close(asset_address, netting2_address, peer1_address, peer1_last_sent_transfers)

    assert client.isopen(asset_address, netting1_address) is False
    assert client.isopen(asset_address, netting2_address) is False

    client.deposit(asset_address, netting2_address, peer3_address, 21)

    assert client.isopen(asset_address, netting1_address) is False
    assert client.isopen(asset_address, netting2_address) is True

    client.update_transfer(asset_address, netting1_address, peer2_address, peer2_last_sent_transfer)

    assert client.isopen(asset_address, netting1_address) is False
    assert client.isopen(asset_address, netting2_address) is True
