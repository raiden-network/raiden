# -*- coding: utf8 -*-
import pytest

from raiden.tests.utils.transfer import (
    direct_transfer,
    mediated_transfer,
    channel,
    get_sent_transfer
)
from raiden.utils import sha3

@pytest.mark.parametrize('privatekey_seed', ['fullnetwork:{}'])
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [2])
@pytest.mark.parametrize('deposit', [2 ** 20])
def test_fullnetwork(raiden_chain):
    app0, app1, app2 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    asset_address = app0.raiden.chain.default_registry.asset_addresses()[0]

    amount = 80
    direct_transfer(app0, app1, asset_address, amount)
    # Assert default identifier is generated correctly
    address = app0.raiden.address
    target = app1.raiden.address
    # asset_manager = app0.raiden.get_manager_by_asset_address(asset_address.decode('hex'))
    asset_manager = app0.raiden.get_manager_by_asset_address(asset_address)
    expected_hash = sha3("{}{}{}".format(
        address,
        asset_manager.partneraddress_channel[target].our_state.nonce - 1,
        asset_manager.partneraddress_channel[target].external_state.netting_channel.address
    ))
    expected_identifier = int(expected_hash[0:8].encode('hex'), 16)

    fchannel = channel(app0, app1, asset_address)
    last_transfer = get_sent_transfer(fchannel, 0)

    assert last_transfer.identifier == expected_identifier

    amount = 50
    direct_transfer(app1, app2, asset_address, amount)

    amount = 30
    mediated_transfer(
        app1,
        app2,
        asset_address,
        amount,
        1  # TODO: fill in identifier
    )
