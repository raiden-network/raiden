# -*- coding: utf-8 -*-
import pytest

from raiden.utils import make_address, get_contract_path, privatekey_to_address
from raiden.network.discovery import ContractDiscovery


@pytest.mark.parametrize('number_of_nodes', [1])
def test_endpointregistry(private_keys, blockchain_services):
    chain = blockchain_services.blockchain_services[0]
    my_address = privatekey_to_address(private_keys[0])

    endpointregistry_address = chain.deploy_contract(
        'EndpointRegistry',
        get_contract_path('EndpointRegistry.sol'),
    )
    discovery_proxy = chain.discovery(endpointregistry_address)

    contract_discovery = ContractDiscovery(my_address, discovery_proxy)

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
