from raiden.constants import BLOCK_ID_LATEST
from raiden.network.proxies.custom_token import CustomToken
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.smartcontracts import is_tx_hash_bytes


def test_custom_token(service_registry_address, private_keys, web3, contract_manager):
    block_identifier = BLOCK_ID_LATEST
    c1_client = JSONRPCClient(web3, private_keys[0])
    c1_service_proxy = ServiceRegistry(
        jsonrpc_client=c1_client,
        service_registry_address=service_registry_address,
        contract_manager=contract_manager,
        block_identifier=block_identifier,
    )
    token_address = c1_service_proxy.token_address(block_identifier=block_identifier)
    c1_token_proxy = CustomToken(
        jsonrpc_client=c1_client,
        token_address=token_address,
        contract_manager=contract_manager,
        block_identifier=block_identifier,
    )

    c2_client = JSONRPCClient(web3, private_keys[1])

    mint_amount = 1000 * 10 ** 18
    tx_hash = c1_token_proxy.mint_for(mint_amount, c2_client.address)
    # check that we return a correctly formatted transaction_hash for a successful tx
    assert is_tx_hash_bytes(tx_hash)
    assert c1_token_proxy.balance_of(c2_client.address) == mint_amount
    assert c1_token_proxy.balance_of(c1_client.address) == 0

    tx_hash = c1_token_proxy.mint(mint_amount)
    assert is_tx_hash_bytes(tx_hash)
    assert c1_token_proxy.balance_of(c1_client.address) == mint_amount
