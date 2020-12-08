from typing import List

import gevent
import pytest
from eth_typing import Address, BlockNumber
from web3 import Web3

from raiden.constants import BLOCK_ID_LATEST, GENESIS_BLOCK_NUMBER
from raiden.exceptions import BrokenPreconditionError
from raiden.network.proxies.proxy_manager import ProxyManager, ProxyManagerMetadata
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.smartcontracts import is_tx_hash_bytes
from raiden.utils.typing import PrivateKey, TokenAmount, UserDepositAddress
from raiden_contracts.contract_manager import ContractManager


@pytest.mark.parametrize("number_of_nodes", [1])
def test_user_deposit_proxy_withdraw(
    private_keys: List[bytes],
    web3: Web3,
    contract_manager: ContractManager,
    user_deposit_address: Address,
):
    c0_client = JSONRPCClient(web3, PrivateKey(private_keys[0]))
    c0_proxy_manager = ProxyManager(
        rpc_client=c0_client,
        contract_manager=contract_manager,
        metadata=ProxyManagerMetadata(
            token_network_registry_deployed_at=GENESIS_BLOCK_NUMBER,
            filters_start_at=GENESIS_BLOCK_NUMBER,
        ),
    )
    c0_user_deposit_proxy = c0_proxy_manager.user_deposit(
        UserDepositAddress(user_deposit_address), BLOCK_ID_LATEST
    )

    withdraw_plan = c0_user_deposit_proxy.get_withdraw_plan(c0_client.address, BLOCK_ID_LATEST)

    # There should be no withdraw plan
    assert withdraw_plan.withdraw_block == 0
    assert withdraw_plan.withdraw_amount == 0

    initial_deposit = c0_user_deposit_proxy.get_total_deposit(c0_client.address, BLOCK_ID_LATEST)

    # None of these are valid plan_withdraw amounts
    for value in [-1, 0, initial_deposit + 1]:
        with pytest.raises(BrokenPreconditionError):
            c0_user_deposit_proxy.plan_withdraw(TokenAmount(value), BLOCK_ID_LATEST)

    # With no plan any withdraw must fail in the precondition check
    with pytest.raises(BrokenPreconditionError):
        c0_user_deposit_proxy.withdraw(TokenAmount(1), BLOCK_ID_LATEST)

    withdraw_amount = TokenAmount(initial_deposit // 2)
    transaction_hash, withdraw_block = c0_user_deposit_proxy.plan_withdraw(
        withdraw_amount, BLOCK_ID_LATEST
    )
    assert is_tx_hash_bytes(transaction_hash)

    # The effective balance must take the planned withdraw into account
    effective_balance_after_withdraw_plan = c0_user_deposit_proxy.effective_balance(
        c0_client.address, BLOCK_ID_LATEST
    )
    assert effective_balance_after_withdraw_plan == initial_deposit - withdraw_amount

    # Wait until target block - 1.
    # We set the retry timeout to 0.1 to make sure there is enough time for the failing case
    # below.
    c0_client.wait_until_block(BlockNumber(withdraw_block - 1), retry_timeout=0.1)

    #  Withdraw should still fail
    with pytest.raises(BrokenPreconditionError):
        c0_user_deposit_proxy.withdraw(TokenAmount(withdraw_amount), BLOCK_ID_LATEST)

    # Wait the final block
    c0_user_deposit_proxy.client.wait_until_block(withdraw_block)

    # Now withdraw must succeed
    transaction_hash = c0_user_deposit_proxy.withdraw(
        TokenAmount(withdraw_amount), BLOCK_ID_LATEST
    )
    assert is_tx_hash_bytes(transaction_hash)

    # The current balance must now match the reduced value
    new_current_balance = c0_user_deposit_proxy.get_balance(c0_client.address, BLOCK_ID_LATEST)
    assert new_current_balance == initial_deposit - withdraw_amount

    # Deposit again after the funds were withdrawn
    amount_to_deposit = 1
    tasks = set()
    # Force a race condition between deposits, letting successive, concurrent calls
    # wait for the first inflight transaction
    for _ in range(3):
        task = gevent.spawn(
            c0_user_deposit_proxy.approve_and_deposit,
            beneficiary=c0_client.address,
            # the total deposit needs to increase monotonically in the contract
            total_deposit=initial_deposit + amount_to_deposit,
            given_block_identifier=BLOCK_ID_LATEST,
        )
        tasks.add(task)
    results = gevent.joinall(tasks, raise_error=True)
    # All tx have the same deposit,
    # so one of them should successfully transact,
    # while all others should wait for the inflight transaction
    # All calls should then be associated to the same on-chain transaction
    tx_hashes = set(result.get() for result in results)
    assert len(tx_hashes) == 1
    assert is_tx_hash_bytes(tx_hashes.pop())
