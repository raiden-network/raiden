from copy import deepcopy
from typing import Any, Dict

import pytest

from raiden.app import App
from raiden.constants import Environment
from raiden.ui.startup import setup_contracts_or_exit, setup_environment, setup_network_id_or_exit
from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_SERVICE_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    CONTRACT_USER_DEPOSIT,
)


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


def raiden_contracts_in_data(contracts: Dict[str, Any]) -> bool:
    return (
        CONTRACT_SECRET_REGISTRY in contracts and
        CONTRACT_TOKEN_NETWORK_REGISTRY in contracts and
        CONTRACT_ENDPOINT_REGISTRY in contracts
    )


def service_contracts_in_data(contracts: Dict[str, Any]) -> bool:
    return (
        CONTRACT_SERVICE_REGISTRY in contracts and
        CONTRACT_USER_DEPOSIT in contracts
    )


def test_setup_contracts():
    # Mainnet production
    config = {'environment_type': Environment.PRODUCTION}
    contracts, addresses_known = setup_contracts_or_exit(config, 1)
    assert 'contracts_path' in config
    assert addresses_known
    assert raiden_contracts_in_data(contracts)
    assert not service_contracts_in_data(contracts)

    # Mainnet development -- NOT allowed
    config = {'environment_type': Environment.DEVELOPMENT}
    with pytest.raises(SystemExit):
        setup_contracts_or_exit(config, 1)

    # Ropsten production
    config = {'environment_type': Environment.PRODUCTION}
    contracts, addresses_known = setup_contracts_or_exit(config, 3)
    assert 'contracts_path' in config
    assert addresses_known
    assert raiden_contracts_in_data(contracts)
    assert not service_contracts_in_data(contracts)

    # Ropsten development
    config = {'environment_type': Environment.DEVELOPMENT}
    contracts, addresses_known = setup_contracts_or_exit(config, 3)
    assert 'contracts_path' in config
    assert addresses_known
    assert raiden_contracts_in_data(contracts)
    assert service_contracts_in_data(contracts)

    # Rinkeby production
    config = {'environment_type': Environment.PRODUCTION}
    contracts, addresses_known = setup_contracts_or_exit(config, 4)
    assert 'contracts_path' in config
    assert addresses_known
    assert raiden_contracts_in_data(contracts)
    assert not service_contracts_in_data(contracts)

    # Rinkeby development
    config = {'environment_type': Environment.DEVELOPMENT}
    contracts, addresses_known = setup_contracts_or_exit(config, 4)
    assert 'contracts_path' in config
    assert addresses_known
    assert raiden_contracts_in_data(contracts)
    assert service_contracts_in_data(contracts)

    # Kovan production
    config = {'environment_type': Environment.PRODUCTION}
    contracts, addresses_known = setup_contracts_or_exit(config, 42)
    assert 'contracts_path' in config
    assert addresses_known
    assert raiden_contracts_in_data(contracts)
    assert not service_contracts_in_data(contracts)

    # Kovan development
    config = {'environment_type': Environment.DEVELOPMENT}
    contracts, addresses_known = setup_contracts_or_exit(config, 42)
    assert 'contracts_path' in config
    assert addresses_known
    assert raiden_contracts_in_data(contracts)
    assert service_contracts_in_data(contracts)

    # random private network production
    config = {'environment_type': Environment.PRODUCTION}
    contracts, addresses_known = setup_contracts_or_exit(config, 5257)
    assert 'contracts_path' in config
    assert not addresses_known
    assert not raiden_contracts_in_data(contracts)
    assert not service_contracts_in_data(contracts)

    # random private network development
    config = {'environment_type': Environment.DEVELOPMENT}
    contracts, addresses_known = setup_contracts_or_exit(config, 5257)
    assert 'contracts_path' in config
    assert not addresses_known
    assert not raiden_contracts_in_data(contracts)
    assert not service_contracts_in_data(contracts)
