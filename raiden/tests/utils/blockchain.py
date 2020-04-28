from raiden.api.debug import get_contract_events
from raiden.blockchain.events import ALL_EVENTS
from raiden.constants import BLOCK_ID_LATEST, GENESIS_BLOCK_NUMBER
from raiden.network.proxies.proxy_manager import ProxyManager
from raiden.utils.typing import (
    Address,
    BlockIdentifier,
    Dict,
    List,
    Optional,
    SecretRegistryAddress,
)
from raiden_contracts.constants import CONTRACT_SECRET_REGISTRY
from raiden_contracts.contract_manager import ContractManager


def get_secret_registry_events(
    proxy_manager: ProxyManager,
    secret_registry_address: SecretRegistryAddress,
    contract_manager: ContractManager,
    events: Optional[List[str]] = ALL_EVENTS,
    from_block: BlockIdentifier = GENESIS_BLOCK_NUMBER,
    to_block: BlockIdentifier = BLOCK_ID_LATEST,
) -> List[Dict]:  # pragma: no unittest
    """ Helper to get all events of a SecretRegistry contract.

    **Do not use with production code**, querying events over large block
    ranges is extremenly slow and will result in timeouts.
    """

    return get_contract_events(
        proxy_manager,
        contract_manager.get_contract_abi(CONTRACT_SECRET_REGISTRY),
        Address(secret_registry_address),
        events,
        from_block,
        to_block,
    )
