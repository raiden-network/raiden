# -*- coding: utf8 -*-
import pytest

from raiden.tests.utils.transfer import direct_transfer, mediated_transfer


@pytest.mark.parametrize('privatekey_seed', ['fullnetwork:{}'])
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [2])
@pytest.mark.parametrize('deposit', [2 ** 20])
def test_fullnetwork(raiden_chain):
    app0, app1, app2 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    asset_address = app0.raiden.chain.default_registry.asset_addresses()[0]

    amount = 80
    direct_transfer(app0, app1, asset_address, amount)

    amount = 50
    direct_transfer(app1, app2, asset_address, amount)

    amount = 30
    mediated_transfer(app1, app2, asset_address, amount)
