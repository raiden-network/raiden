# -*- coding: utf8 -*-
import pytest

from ethereum import _solidity

from raiden.utils import make_address, get_contract_path
from raiden.network.discovery import ContractDiscovery


@pytest.mark.parametrize('blockchain_type', ['geth'])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('poll_timeout', [80])
def test_endpointregistry(blockchain_services, poll_timeout):
    chain = blockchain_services[0]
    my_address = chain.node_address

    # deploy discovery contract
    discovery_contract_path = get_contract_path('EndpointRegistry.sol')
    discovery_contracts = _solidity.compile_file(discovery_contract_path, libraries=dict())

    endpoinregistry_proxy = chain.client.deploy_solidity_contract(
        my_address,
        'EndpointRegistry',
        discovery_contracts,
        dict(),
        tuple(),
        timeout=poll_timeout,
    )

    endpointregistry_address = endpoinregistry_proxy.address
    contract_discovery = ContractDiscovery(
        chain,
        endpointregistry_address,
    )

    unregistered_address = make_address()

    # get should raise for unregistered addresses
    with pytest.raises(KeyError):
        contract_discovery.get(my_address)

    with pytest.raises(KeyError):
        contract_discovery.get(unregistered_address)

    assert contract_discovery.nodeid_by_host_port(('127.0.0.1', 44444)) is None

    contract_discovery.register(my_address, '127.0.0.1', 44444)

    assert contract_discovery.nodeid_by_host_port(('127.0.0.1', 44444)) == my_address
    assert contract_discovery.get(my_address) == ('127.0.0.1', 44444)

    contract_discovery.register(my_address, '127.0.0.1', 88888)

    assert contract_discovery.nodeid_by_host_port(('127.0.0.1', 88888)) == my_address
    assert contract_discovery.get(my_address) == ('127.0.0.1', 88888)

    with pytest.raises(KeyError):
        contract_discovery.get(unregistered_address)
