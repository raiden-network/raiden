# -*- coding: utf8 -*-
import pytest
import gevent

from raiden.network.discovery import ContractDiscovery, Discovery


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('poll_timeout', [80])
@pytest.mark.parametrize('local', [True, False])
def test_api_compliance(discovery_blockchain, local):
    contract_discovery_instance, address = discovery_blockchain

    if local:
        contract_discovery_instance = Discovery()
        assert isinstance(contract_discovery_instance, Discovery)
    else:
        assert isinstance(contract_discovery_instance, ContractDiscovery)

    # test that `get` for unknown address raises KeyError
    with pytest.raises(KeyError):
        assert contract_discovery_instance.get(('01' * 20).decode('hex')) is None

    assert contract_discovery_instance.nodeid_by_host_port(('127.0.0.1', 44444)) is None

    # `update_endpoint` and 'classic' `register` do the same
    contract_discovery_instance.register(address, '127.0.0.1', 44444)
    not local and gevent.sleep(30)
    assert contract_discovery_instance.nodeid_by_host_port(('127.0.0.1', 44444)) == address
    assert contract_discovery_instance.get(address) == ('127.0.0.1', 44444)

    # `register`ing twice does update do the same
    contract_discovery_instance.register(address, '127.0.0.1', 88888)
    not local and gevent.sleep(30)
    assert contract_discovery_instance.nodeid_by_host_port(('127.0.0.1', 88888)) == address
    assert contract_discovery_instance.get(address) == ('127.0.0.1', 88888)
