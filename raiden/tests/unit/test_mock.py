import pytest

from raiden.exceptions import InvalidAddress
from raiden.network.discovery import Discovery
from raiden.tests.utils.factories import make_address


def test_mock_registry_api_compliance():
    address = make_address()
    contract_discovery_instance = Discovery()

    # `get` for unknown address raises
    with pytest.raises(InvalidAddress):
        contract_discovery_instance.get(address)

    # `update_endpoint` and 'classic' `register` do the same
    contract_discovery_instance.register(address, '127.0.0.1', 44444)
    assert contract_discovery_instance.get(address) == ('127.0.0.1', 44444)

    # `register`ing twice does update do the same
    contract_discovery_instance.register(address, '127.0.0.1', 88888)
    assert contract_discovery_instance.get(address) == ('127.0.0.1', 88888)
