# -*- coding: utf8 -*-
import pytest


@pytest.mark.parametrize('privatekey_seed', ['create_network:{}'])
@pytest.mark.parametrize('number_of_assets', [2])
@pytest.mark.parametrize('number_of_nodes', [5])
def test_create_network(raiden_network, number_of_nodes):
    assert len(raiden_network) == number_of_nodes

    # all apps must reference the default registry
    default_address = raiden_network[0].raiden.chain.default_registry.address
    for app in raiden_network:
        assert app.raiden.chain.default_registry.address == default_address

    # All apps must have 2 asset managers (one per each asset)
    for app in raiden_network:
        assert len(app.raiden.managers_by_asset_address) == 2

    # All apps must have uniq private keys
    private_keys = set(
        app.raiden.privkey
        for app in raiden_network
    )
    assert len(private_keys) == number_of_nodes
