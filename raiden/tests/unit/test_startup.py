from copy import deepcopy
from typing import Any, Dict

import pytest
from gevent import server

from raiden.app import App
from raiden.constants import Environment, RoutingMode
from raiden.network.transport import UDPTransport
from raiden.tests.utils.factories import make_address
from raiden.tests.utils.mocks import MockChain, MockWeb3, patched_get_for_succesful_pfs_info
from raiden.ui.checks import check_ethereum_network_id
from raiden.ui.startup import (
    setup_contracts_or_exit,
    setup_environment,
    setup_proxies_or_exit,
    setup_udp_or_exit,
)
from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_SERVICE_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    CONTRACT_USER_DEPOSIT,
)


def test_check_network_id_raises_with_mismatching_ids():
    check_ethereum_network_id(68, MockWeb3(68))

    with pytest.raises(SystemExit):
        check_ethereum_network_id(61, MockWeb3(68))


@pytest.mark.parametrize("netid", [1, 3, 4, 42, 5, 627])
def test_setup_does_not_raise_with_matching_ids(netid):
    """Test that network setup works for the known network ids"""
    check_ethereum_network_id(netid, MockWeb3(netid))


def test_setup_environment():
    # Test that setting development works
    config = deepcopy(App.DEFAULT_CONFIG)
    setup_environment(config, Environment.DEVELOPMENT)
    assert config["environment_type"] == Environment.DEVELOPMENT

    # Test that setting production sets private rooms for Matrix
    config = deepcopy(App.DEFAULT_CONFIG)
    setup_environment(config, Environment.PRODUCTION)
    assert config["environment_type"] == Environment.PRODUCTION
    assert config["transport"]["matrix"]["private_rooms"] is True


def raiden_contracts_in_data(contracts: Dict[str, Any]) -> bool:
    return (
        CONTRACT_SECRET_REGISTRY in contracts
        and CONTRACT_TOKEN_NETWORK_REGISTRY in contracts
        and CONTRACT_ENDPOINT_REGISTRY in contracts
    )


def service_contracts_in_data(contracts: Dict[str, Any]) -> bool:
    return CONTRACT_SERVICE_REGISTRY in contracts and CONTRACT_USER_DEPOSIT in contracts


def test_setup_contracts():
    # Mainnet production
    config = {"environment_type": Environment.PRODUCTION}
    contracts = setup_contracts_or_exit(config, 1)
    assert "contracts_path" in config
    assert raiden_contracts_in_data(contracts)
    assert not service_contracts_in_data(contracts)

    # Mainnet development -- NOT allowed
    config = {"environment_type": Environment.DEVELOPMENT}
    with pytest.raises(SystemExit):
        setup_contracts_or_exit(config, 1)

    # Ropsten production
    config = {"environment_type": Environment.PRODUCTION}
    contracts = setup_contracts_or_exit(config, 3)
    assert "contracts_path" in config
    assert raiden_contracts_in_data(contracts)
    assert not service_contracts_in_data(contracts)

    # Ropsten development
    config = {"environment_type": Environment.DEVELOPMENT}
    contracts = setup_contracts_or_exit(config, 3)
    assert "contracts_path" in config
    assert raiden_contracts_in_data(contracts)
    assert service_contracts_in_data(contracts)

    # Rinkeby production
    config = {"environment_type": Environment.PRODUCTION}
    contracts = setup_contracts_or_exit(config, 4)
    assert "contracts_path" in config
    assert raiden_contracts_in_data(contracts)
    assert not service_contracts_in_data(contracts)

    # Rinkeby development
    config = {"environment_type": Environment.DEVELOPMENT}
    contracts = setup_contracts_or_exit(config, 4)
    assert "contracts_path" in config
    assert raiden_contracts_in_data(contracts)
    assert service_contracts_in_data(contracts)

    # Goerli production TODO: Uncomment when production contracts are deployed in Goerli
    # config = {'environment_type': Environment.PRODUCTION}
    # contracts = setup_contracts_or_exit(config, 5)
    # assert 'contracts_path' in config
    # assert raiden_contracts_in_data(contracts)
    # assert not service_contracts_in_data(contracts)

    # Goerli development
    config = {"environment_type": Environment.DEVELOPMENT}
    contracts = setup_contracts_or_exit(config, 5)
    assert "contracts_path" in config
    assert raiden_contracts_in_data(contracts)
    assert service_contracts_in_data(contracts)

    # Kovan production
    config = {"environment_type": Environment.PRODUCTION}
    contracts = setup_contracts_or_exit(config, 42)
    assert "contracts_path" in config
    assert raiden_contracts_in_data(contracts)
    assert not service_contracts_in_data(contracts)

    # Kovan development
    config = {"environment_type": Environment.DEVELOPMENT}
    contracts = setup_contracts_or_exit(config, 42)
    assert "contracts_path" in config
    assert raiden_contracts_in_data(contracts)
    assert service_contracts_in_data(contracts)

    # random private network production
    config = {"environment_type": Environment.PRODUCTION}
    contracts = setup_contracts_or_exit(config, 5257)
    assert "contracts_path" in config
    assert not raiden_contracts_in_data(contracts)
    assert not service_contracts_in_data(contracts)

    # random private network development
    config = {"environment_type": Environment.DEVELOPMENT}
    contracts = setup_contracts_or_exit(config, 5257)
    assert "contracts_path" in config
    assert not raiden_contracts_in_data(contracts)
    assert not service_contracts_in_data(contracts)


def test_setup_proxies_raiden_addresses_are_given():
    """
    Test that startup for proxies works fine if only raiden addresses only are given
    """

    network_id = 42
    config = {"environment_type": Environment.DEVELOPMENT, "chain_id": network_id, "services": {}}
    contracts = {}
    blockchain_service = MockChain(network_id=network_id, node_address=make_address())

    proxies = setup_proxies_or_exit(
        config=config,
        tokennetwork_registry_contract_address=make_address(),
        secret_registry_contract_address=make_address(),
        endpoint_registry_contract_address=make_address(),
        user_deposit_contract_address=None,
        service_registry_contract_address=None,
        blockchain_service=blockchain_service,
        contracts=contracts,
        routing_mode=RoutingMode.BASIC,
        pathfinding_service_address=None,
    )
    assert proxies
    assert proxies.token_network_registry
    assert proxies.secret_registry
    assert not proxies.user_deposit
    assert not proxies.service_registry


@pytest.mark.parametrize("routing_mode", [RoutingMode.PFS, RoutingMode.BASIC])
def test_setup_proxies_all_addresses_are_given(routing_mode):
    """
    Test that startup for proxies works fine if all addresses are given and routing is basic
    """

    network_id = 42
    config = {"environment_type": Environment.DEVELOPMENT, "chain_id": network_id, "services": {}}
    contracts = {}
    blockchain_service = MockChain(network_id=network_id, node_address=make_address())

    with patched_get_for_succesful_pfs_info():
        proxies = setup_proxies_or_exit(
            config=config,
            tokennetwork_registry_contract_address=make_address(),
            secret_registry_contract_address=make_address(),
            endpoint_registry_contract_address=make_address(),
            user_deposit_contract_address=make_address(),
            service_registry_contract_address=make_address(),
            blockchain_service=blockchain_service,
            contracts=contracts,
            routing_mode=routing_mode,
            pathfinding_service_address="my-pfs",
        )
    assert proxies
    assert proxies.token_network_registry
    assert proxies.secret_registry
    assert proxies.user_deposit
    assert proxies.service_registry


@pytest.mark.parametrize("routing_mode", [RoutingMode.PFS, RoutingMode.BASIC])
def test_setup_proxies_all_addresses_are_known(routing_mode):
    """
    Test that startup for proxies works fine if all addresses are given and routing is basic
    """

    network_id = 42
    config = {"environment_type": Environment.DEVELOPMENT, "chain_id": network_id, "services": {}}
    contracts = setup_contracts_or_exit(config, network_id)
    blockchain_service = MockChain(network_id=network_id, node_address=make_address())

    with patched_get_for_succesful_pfs_info():
        proxies = setup_proxies_or_exit(
            config=config,
            tokennetwork_registry_contract_address=None,
            secret_registry_contract_address=None,
            endpoint_registry_contract_address=None,
            user_deposit_contract_address=None,
            service_registry_contract_address=None,
            blockchain_service=blockchain_service,
            contracts=contracts,
            routing_mode=routing_mode,
            pathfinding_service_address="my-pfs",
        )
    assert proxies
    assert proxies.token_network_registry
    assert proxies.secret_registry
    assert proxies.user_deposit
    assert proxies.service_registry


def test_setup_proxies_no_service_registry_but_pfs():
    """
    Test that if no service registry is provided but a manual pfs address is given then startup
    still works

    Regression test for https://github.com/raiden-network/raiden/issues/3740
    """

    network_id = 42
    config = {"environment_type": Environment.DEVELOPMENT, "chain_id": network_id, "services": {}}
    contracts = {}
    blockchain_service = MockChain(network_id=network_id, node_address=make_address())

    with patched_get_for_succesful_pfs_info():
        proxies = setup_proxies_or_exit(
            config=config,
            tokennetwork_registry_contract_address=make_address(),
            secret_registry_contract_address=make_address(),
            endpoint_registry_contract_address=make_address(),
            user_deposit_contract_address=make_address(),
            service_registry_contract_address=None,
            blockchain_service=blockchain_service,
            contracts=contracts,
            routing_mode=RoutingMode.PFS,
            pathfinding_service_address="my-pfs",
        )
    assert proxies


def test_setup_proxies_no_service_registry_and_no_pfs_address_but_requesting_pfs():
    """
    Test that if pfs routing mode is requested and no address or service registry is given
    then the client exits with an error message
    """

    network_id = 42
    config = {"environment_type": Environment.DEVELOPMENT, "chain_id": network_id, "services": {}}
    contracts = {}
    blockchain_service = MockChain(network_id=network_id, node_address=make_address())

    with pytest.raises(SystemExit):
        with patched_get_for_succesful_pfs_info():
            setup_proxies_or_exit(
                config=config,
                tokennetwork_registry_contract_address=make_address(),
                secret_registry_contract_address=make_address(),
                endpoint_registry_contract_address=make_address(),
                user_deposit_contract_address=make_address(),
                service_registry_contract_address=None,
                blockchain_service=blockchain_service,
                contracts=contracts,
                routing_mode=RoutingMode.PFS,
                pathfinding_service_address=None,
            )


def test_setup_udp_or_exit(raiden_udp_ports):
    network_id = 42
    config = deepcopy(App.DEFAULT_CONFIG)
    config["network_id"] = network_id
    config["environment_type"] = Environment.DEVELOPMENT
    host = "127.0.0.1"
    port = raiden_udp_ports[0]
    config["socket"] = server._udp_socket((host, port))  # pylint: disable=protected-access
    contracts = {}
    our_address = make_address()
    blockchain_service = MockChain(network_id=network_id, node_address=make_address())
    # set a big fake balance for us, to pass the test of sufficient gas for discovery transaction
    blockchain_service.client.balances_mapping[our_address] = 99999999999999999
    transport, discovery = setup_udp_or_exit(
        config=config,
        blockchain_service=blockchain_service,
        address=our_address,
        contracts=contracts,
        endpoint_registry_contract_address=make_address(),
    )
    assert isinstance(transport, UDPTransport)
    assert discovery


def test_setup_udp_or_exit_insufficient_balance():
    network_id = 42
    config = deepcopy(App.DEFAULT_CONFIG)
    config["network_id"] = network_id
    config["environment_type"] = Environment.DEVELOPMENT
    contracts = {}
    our_address = make_address()
    blockchain_service = MockChain(network_id=network_id, node_address=make_address())
    # we don't have sufficient balance, so client should exit with a message
    blockchain_service.client.balances_mapping[our_address] = 1
    with pytest.raises(SystemExit):
        setup_udp_or_exit(
            config=config,
            blockchain_service=blockchain_service,
            address=our_address,
            contracts=contracts,
            endpoint_registry_contract_address=make_address(),
        )
