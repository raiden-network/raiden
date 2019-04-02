from copy import deepcopy

import pytest

from raiden.app import App
from raiden.constants import Environment
from raiden.ui.startup import setup_environment, setup_network_id_or_exit


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


def test_setup_environment():
    # Test that setting development works
    config = deepcopy(App.DEFAULT_CONFIG)
    assert Environment.DEVELOPMENT == setup_environment(config, Environment.DEVELOPMENT)
    assert config['environment_type'] == Environment.DEVELOPMENT

    # Test that setting production sets private rooms for Matrix
    config = deepcopy(App.DEFAULT_CONFIG)
    assert Environment.PRODUCTION == setup_environment(config, Environment.PRODUCTION)
    assert config['environment_type'] == Environment.PRODUCTION
    assert config['transport']['matrix']['private_rooms'] is True
