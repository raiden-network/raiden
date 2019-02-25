import pytest

from raiden.exceptions import UnknownAddress
from raiden.tests.utils.factories import make_address
from raiden.utils import host_port_to_endpoint, privatekey_to_address, safe_gas_limit
from raiden_contracts.constants import GAS_REQUIRED_FOR_ENDPOINT_REGISTER


@pytest.mark.parametrize('number_of_nodes', [1])
def test_endpointregistry(
        private_keys,
        endpoint_discovery_services,
):
    my_address = privatekey_to_address(private_keys[0])

    contract_discovery = endpoint_discovery_services[0]

    unregistered_address = make_address()

    # get should raise for unregistered addresses
    with pytest.raises(UnknownAddress):
        contract_discovery.get(my_address)

    with pytest.raises(UnknownAddress):
        contract_discovery.get(unregistered_address)

    contract_discovery.register(my_address, '127.0.0.1', 44444)
    assert contract_discovery.get(my_address) == ('127.0.0.1', 44444)

    contract_discovery.register(my_address, '127.0.0.1', 88888)
    assert contract_discovery.get(my_address) == ('127.0.0.1', 88888)

    with pytest.raises(UnknownAddress):
        contract_discovery.get(unregistered_address)


@pytest.mark.parametrize('number_of_nodes', [1])
def test_endpointregistry_gas(endpoint_discovery_services):
    """ GAS_REQUIRED_FOR_ENDPOINT_REGISTER value must be equal to the gas required to call
    registerEndpoint.
    """
    contract_discovery = endpoint_discovery_services[0]
    discovery_proxy = contract_discovery.discovery_proxy
    endpoint = host_port_to_endpoint('127.0.0.1', 44444)

    transaction_hash = discovery_proxy.proxy.transact(
        'registerEndpoint',
        safe_gas_limit(GAS_REQUIRED_FOR_ENDPOINT_REGISTER),
        endpoint,
    )
    discovery_proxy.client.poll(transaction_hash)

    receipt = discovery_proxy.client.get_transaction_receipt(transaction_hash)
    msg = 'the transaction failed, check if it was because of the gas being too low'
    assert receipt['status'] != 0, msg
