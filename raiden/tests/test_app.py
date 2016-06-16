# -*- coding: utf8 -*-
import pytest


@pytest.mark.parametrize('privatekey_seed', ['create_network:{}'])
@pytest.mark.parametrize('number_of_assets', [2])
@pytest.mark.parametrize('number_of_nodes', [10])
def test_create_network(raiden_network):
    assert len(raiden_network) == 10

    # All apps must reference the same chain
    for app in raiden_network:
        assert app.raiden.chain == raiden_network[0].raiden.chain

    # All apps must have 2 asset managers (one per each asset)
    for app in raiden_network:
        assert len(set(app.raiden.assetmanagers.keys())) == 2

    # All apps must have uniq private keys
    private_keys = set(app.raiden.privkey for app in raiden_network)
    assert len(private_keys) == 10
