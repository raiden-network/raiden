import pytest

from raiden.ui.startup import setup_network_id_or_exit


class MockWeb3Version():

    def __init__(self, netid):
        self.network = netid


class MockWeb3():

    def __init__(self, netid):
        self.version = MockWeb3Version(netid)


def test_setup_network_id():
    config = {}

    # Normal test
    netid, known = setup_network_id_or_exit(config, 68, MockWeb3(68))
    assert netid == 68
    assert not known
    assert config['chain_id'] == netid

    # Chain id different than the one in the ethereum client
    with pytest.raises(SystemExit):
        setup_network_id_or_exit(config, 61, MockWeb3(68))

    # Known network ids
    for netid in (1, 3, 4, 42, 627):
        config = {}
        network_id, known = setup_network_id_or_exit(config, netid, MockWeb3(netid))
        assert network_id == netid
        assert known
        assert config['chain_id'] == netid
