import pytest

from pathfinding_service.utils.blockchain_listener import BlockchainListener
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK


@pytest.fixture
def blockchain_listener(web3, contracts_manager, token_network):
    blockchain_listener = BlockchainListener(
        web3=web3,
        contract_manager=contracts_manager,
        contract_name=CONTRACT_TOKEN_NETWORK,
        contract_address=token_network.address,
        poll_interval=0,
    )
    return blockchain_listener
