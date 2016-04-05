from raiden.app import create_network


def test_create_network():
    apps = create_network(num_nodes=10, num_assets=2, channels_per_node=4)
    assert len(apps) == 10

    # All apps must reference the same chain
    for app in apps:
        assert app.raiden.chain == apps[0].raiden.chain

    # All apps must have 2 asset managers (one per each asset)
    for app in apps:
        assert len(set(app.raiden.assetmanagers.keys())) == 2

    # All apps must have uniq private keys
    assert len(set([app.raiden.privkey for app in apps])) == 10
