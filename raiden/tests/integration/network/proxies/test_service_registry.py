from eth_utils import to_checksum_address

from raiden.network.pathfinding import get_random_service
from raiden.network.proxies import ServiceRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.factories import HOP1
from raiden.utils import privatekey_to_address


def test_service_registry_random_pfs(
        service_registry_address,
        private_keys,
        web3,
        contract_manager,
):
    urls = ['http://foo', 'http://boo', 'http://coo']
    addresses = [
        # to_normalized_address(privatekey_to_address(key))
        to_checksum_address(privatekey_to_address(key))
        for key in private_keys
    ]

    c1_client = JSONRPCClient(web3, private_keys[0])
    c1_service_proxy = ServiceRegistry(
        jsonrpc_client=c1_client,
        service_registry_address=service_registry_address,
        contract_manager=contract_manager,
    )
    c2_client = JSONRPCClient(web3, private_keys[1])
    c2_service_proxy = ServiceRegistry(
        jsonrpc_client=c2_client,
        service_registry_address=service_registry_address,
        contract_manager=contract_manager,
    )
    c3_client = JSONRPCClient(web3, private_keys[2])
    c3_service_proxy = ServiceRegistry(
        jsonrpc_client=c3_client,
        service_registry_address=service_registry_address,
        contract_manager=contract_manager,
    )

    # Test that setting the urls works
    c1_service_proxy.set_url(urls[0])
    c2_service_proxy.set_url(urls[1])
    c3_service_proxy.set_url(urls[2])
    assert c1_service_proxy.service_count('latest') == 3

    # Test that getting the url for each service address works
    for idx, address in enumerate(addresses):
        assert c1_service_proxy.get_service_url('latest', address) == urls[idx]
    # Test that getting the url for a non-existing service address returns None
    assert not c1_service_proxy.get_service_url('latest', to_checksum_address(HOP1))

    # Test that get_service_address by index works
    for idx, address in enumerate(addresses):
        c1_service_proxy.get_service_address('latest', idx) == address
    # Test that getting the address for an index out of bounds returns None
    assert not c1_service_proxy.get_service_address('latest', 9999)

    # Test that getting a random service from the proxy works
    assert get_random_service(c1_service_proxy) in urls
