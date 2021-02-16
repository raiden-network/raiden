from unittest.mock import Mock, patch

import pytest
from eth_utils import to_canonical_address

from raiden.blockchain.decode import update_service_addresses_from_event
from raiden.blockchain.events import decode_raiden_event_to_internal
from raiden.blockchain.filters import RaidenContractFilter
from raiden.constants import BLOCK_ID_LATEST
from raiden.exceptions import BrokenPreconditionError
from raiden.network.pathfinding import get_random_pfs, get_valid_pfs_url
from raiden.settings import RAIDEN_CONTRACT_VERSION
from raiden.tests.utils.factories import HOP1
from raiden.tests.utils.smartcontracts import deploy_service_registry_and_set_urls
from raiden.transfer.events import UpdateServicesAddresses
from raiden.utils.keys import privatekey_to_address
from raiden.utils.typing import FeeAmount, TokenNetworkRegistryAddress
from raiden_contracts.contract_manager import ContractManager, contracts_precompiled_path

token_network_registry_address_test_default = TokenNetworkRegistryAddress(
    to_canonical_address("0xB9633dd9a9a71F22C933bF121d7a22008f66B908")
)


def test_service_registry_set_url(service_registry_address, private_keys, web3, contract_manager):
    c1_service_proxy, _ = deploy_service_registry_and_set_urls(
        private_keys=private_keys,
        web3=web3,
        contract_manager=contract_manager,
        service_registry_address=service_registry_address,
    )
    with pytest.raises(BrokenPreconditionError):
        c1_service_proxy.set_url("")

    with pytest.raises(BrokenPreconditionError):
        c1_service_proxy.set_url("raiden-network.com")


def test_service_registry_random_pfs(
    service_registry_address, private_keys, web3, contract_manager
):
    addresses = [privatekey_to_address(key) for key in private_keys]
    c1_service_proxy, urls = deploy_service_registry_and_set_urls(
        private_keys=private_keys,
        web3=web3,
        contract_manager=contract_manager,
        service_registry_address=service_registry_address,
    )
    assert c1_service_proxy.ever_made_deposits_len(BLOCK_ID_LATEST) == 3

    # Test that getting the url for each service address works
    for idx, address in enumerate(addresses):
        assert c1_service_proxy.get_service_url(BLOCK_ID_LATEST, address) == urls[idx]
    # Test that getting the url for a non-existing service address returns None
    assert c1_service_proxy.get_service_url(BLOCK_ID_LATEST, HOP1) is None

    # Test that get_service_address by index works
    for idx, address in enumerate(addresses):
        assert c1_service_proxy.ever_made_deposits(BLOCK_ID_LATEST, idx) == address

    # Test that getting the address for an index out of bounds returns None
    assert not c1_service_proxy.ever_made_deposits(BLOCK_ID_LATEST, 9999)

    mock_get_pfs_info = Mock()
    mock_get_pfs_info.return_value.price = 100
    with patch("raiden.network.pathfinding.get_pfs_info", mock_get_pfs_info):
        # Make sure that too expensive PFSes are not considered valid
        assert not get_valid_pfs_url(
            c1_service_proxy, 0, BLOCK_ID_LATEST, pathfinding_max_fee=FeeAmount(99)
        )

        # ...but ones with the expected price are fine
        assert (
            get_valid_pfs_url(
                c1_service_proxy, 0, BLOCK_ID_LATEST, pathfinding_max_fee=FeeAmount(100)
            )
            == urls[0]
        )

        # Test that getting a random service from the proxy works
        assert (
            get_random_pfs(c1_service_proxy, BLOCK_ID_LATEST, pathfinding_max_fee=FeeAmount(100))
            in urls
        )


def test_service_registry_events(service_registry_address, private_keys, web3, contract_manager):
    """
    - Test that `RaidenContractFilter` successfully matches on `RegisteredService`.
    - Test that blockchain-event, state_change and raiden-event decoding methods work.
    """
    c1_service_proxy, _ = deploy_service_registry_and_set_urls(
        private_keys=private_keys,
        web3=web3,
        contract_manager=contract_manager,
        service_registry_address=service_registry_address,
    )
    assert c1_service_proxy.ever_made_deposits_len(BLOCK_ID_LATEST) == 3

    # register filter
    event_filter = RaidenContractFilter(service_registry=c1_service_proxy)

    manager = ContractManager(contracts_precompiled_path(RAIDEN_CONTRACT_VERSION))
    flt = event_filter.to_web3_filters(
        contract_manager=manager,
        from_block=0,
        to_block="latest",
        node_address="0x6666666666666666666666666666666666666666",
    )
    web3 = c1_service_proxy.client.web3
    flt[0].pop("_name")
    events = web3.eth.getLogs(flt[0])
    assert len(events) == 3

    ABI = c1_service_proxy.proxy.abi
    decoded_events = [decode_raiden_event_to_internal(ABI, 0, ev) for ev in events]
    assert len(decoded_events) == 3
    state_changes = [update_service_addresses_from_event(ev) for ev in decoded_events]
    assert len(state_changes) == 3
    raiden_events = [UpdateServicesAddresses.from_state_change(sc) for sc in state_changes]
    assert len(raiden_events) == 3
