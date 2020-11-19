from collections import defaultdict

import gevent
import pytest
from web3 import Web3

from raiden.blockchain.events import get_contract_events
from raiden.constants import BLOCK_ID_LATEST, GENESIS_BLOCK_NUMBER, STATE_PRUNING_AFTER_BLOCKS
from raiden.exceptions import NoStateForBlockIdentifier
from raiden.network.proxies.proxy_manager import ProxyManager, ProxyManagerMetadata
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.rpc.client import (
    JSONRPCClient,
    SmartContractCall,
    TransactionEstimated,
    TransactionSent,
)
from raiden.tests.utils.events import must_have_event
from raiden.tests.utils.factories import make_secret
from raiden.tests.utils.smartcontracts import is_tx_hash_bytes
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import Address, BlockNumber, Dict, List, PrivateKey, Secret
from raiden_contracts.constants import CONTRACT_SECRET_REGISTRY
from raiden_contracts.contract_manager import ContractManager


def secret_registry_batch_happy_path(
    proxy_manager: ProxyManager, secret_registry_proxy: SecretRegistry
) -> None:
    secrets = [make_secret() for i in range(4)]
    secrethashes = [sha256_secrethash(secret) for secret in secrets]

    transaction_hashes = secret_registry_proxy.register_secret_batch(secrets=secrets)
    for tx_hash in transaction_hashes:
        assert is_tx_hash_bytes(tx_hash)

    logs = get_contract_events(
        proxy_manager=proxy_manager,
        abi=proxy_manager.contract_manager.get_contract_abi(CONTRACT_SECRET_REGISTRY),
        contract_address=Address(secret_registry_proxy.address),
    )

    for secrethash in secrethashes:
        secret_registered = must_have_event(
            logs, {"event": "SecretRevealed", "args": {"secrethash": secrethash}}
        )
        assert secret_registered, "All secrets from the batch must be registered"

        block = secret_registry_proxy.get_secret_registration_block_by_secrethash(
            secrethash=secrethash, block_identifier=BLOCK_ID_LATEST
        )
        msg = "Block number reported by the proxy and the event must match"
        assert block == secret_registered["block_number"], msg


def test_register_secret_happy_path(
    secret_registry_proxy: SecretRegistry, contract_manager: ContractManager
) -> None:
    """Test happy path of SecretRegistry with a single secret.

    Test that `register_secret` changes the smart contract state by registering
    the secret, this can be verified by the block height and the existence of
    the SecretRegistered event.
    """
    secret = make_secret()
    secrethash = sha256_secrethash(secret)
    secret_unregistered = make_secret()
    secrethash_unregistered = sha256_secrethash(secret_unregistered)

    assert not secret_registry_proxy.is_secret_registered(
        secrethash=secrethash, block_identifier=BLOCK_ID_LATEST
    ), "Test setup is invalid, secret must be unknown"
    assert not secret_registry_proxy.is_secret_registered(
        secrethash=secrethash_unregistered, block_identifier=BLOCK_ID_LATEST
    ), "Test setup is invalid, secret must be unknown"

    secret_registry_proxy.client.wait_until_block(BlockNumber(STATE_PRUNING_AFTER_BLOCKS + 1))

    with pytest.raises(NoStateForBlockIdentifier):
        secret_registry_proxy.is_secret_registered(
            secrethash=secrethash_unregistered, block_identifier=BlockNumber(0)
        )

    secret_registry_proxy.register_secret(secret=secret)

    proxy_manager = ProxyManager(
        rpc_client=secret_registry_proxy.client,
        contract_manager=contract_manager,
        metadata=ProxyManagerMetadata(
            token_network_registry_deployed_at=GENESIS_BLOCK_NUMBER,
            filters_start_at=GENESIS_BLOCK_NUMBER,
        ),
    )
    logs = get_contract_events(
        proxy_manager=proxy_manager,
        abi=proxy_manager.contract_manager.get_contract_abi(CONTRACT_SECRET_REGISTRY),
        contract_address=Address(secret_registry_proxy.address),
    )
    secret_registered = must_have_event(
        logs, {"event": "SecretRevealed", "args": {"secrethash": secrethash}}
    )

    msg = "SecretRegistry.register_secret returned but the SecretRevealed event was not emitted."
    assert secret_registered, msg

    registered_block = secret_registry_proxy.get_secret_registration_block_by_secrethash(
        secrethash=secrethash, block_identifier=BLOCK_ID_LATEST
    )
    msg = (
        "Block height returned by the SecretRegistry.get_secret_registration_block_by_secrethash "
        "does not match the block from the SecretRevealed event."
    )
    assert secret_registered["block_number"] == registered_block, msg

    block = secret_registry_proxy.get_secret_registration_block_by_secrethash(
        secrethash=secrethash_unregistered, block_identifier=BLOCK_ID_LATEST
    )
    assert block is None, "The secret that was not registered must not change block height!"


def test_register_secret_batch_happy_path(
    proxy_manager: ProxyManager, secret_registry_proxy: SecretRegistry
):
    """Test happy path for secret registration batching."""
    secret_registry_batch_happy_path(proxy_manager, secret_registry_proxy)


def test_register_secret_batch_with_pruned_block(
    proxy_manager: ProxyManager,
    secret_registry_proxy: SecretRegistry,
    web3: Web3,
    private_keys: List[PrivateKey],
) -> None:
    """Test secret registration with a pruned given block."""
    rpc_client = JSONRPCClient(web3, private_keys[1])

    # Now wait until this block becomes pruned
    pruned_number = rpc_client.block_number()
    rpc_client.wait_until_block(
        target_block_number=BlockNumber(pruned_number + STATE_PRUNING_AFTER_BLOCKS)
    )
    secret_registry_batch_happy_path(proxy_manager, secret_registry_proxy)


def test_concurrent_secret_registration(secret_registry_proxy: SecretRegistry, monkeypatch):
    """Only one transaction must be sent if multiple greenlets are used to
    register the same secret.

    This checks that Raiden will not send unecessary transactions to register
    the same secret twice, which happened in the past because the same
    ContractSendSecretRegister event was emitted multiple times.

    Note:
        This is testing using the block as `latest`, which may not be the case
        in user code, therefore this behavior is not 100% guaranteed.
    """
    with monkeypatch.context() as m:
        count: Dict[Secret, int] = defaultdict(int)
        transact = secret_registry_proxy.client.transact

        def count_how_many_times_a_secret_is_sent(
            transaction: TransactionEstimated,
        ) -> TransactionSent:
            assert isinstance(transaction.data, SmartContractCall)
            assert isinstance(transaction.data.args, tuple)

            for secret in transaction.data.args[0]:
                count[secret] += 1
                msg = "All secrets must be registered, and they all must be registered only once"
                assert count[secret] == 1, msg

            return transact(transaction)

        m.setattr(secret_registry_proxy.client, "transact", count_how_many_times_a_secret_is_sent)

        # Important: Make sure all secrets are actually used
        secrets = [make_secret() for _ in range(7)]
        greenlets = set()

        # `register_secret` called twice
        for _ in range(2):
            greenlets.add(gevent.spawn(secret_registry_proxy.register_secret, secrets[0]))

        # `register_secret_batch` called twice
        for _ in range(2):
            greenlets.add(gevent.spawn(secret_registry_proxy.register_secret_batch, secrets[1:3]))

        # Calling `register_secret` then `register_secret_batch`
        # Calling `register_secret_batch` then `register_secret`
        for _ in range(2):
            greenlets.add(gevent.spawn(secret_registry_proxy.register_secret, secrets[3]))
            greenlets.add(gevent.spawn(secret_registry_proxy.register_secret_batch, secrets[3:5]))
            greenlets.add(gevent.spawn(secret_registry_proxy.register_secret, secrets[4]))

        # `register_secret_batch` called twice, with different order of the
        # secret
        for _ in range(2):
            greenlets.add(gevent.spawn(secret_registry_proxy.register_secret_batch, secrets[5:7]))
            greenlets.add(
                gevent.spawn(
                    secret_registry_proxy.register_secret_batch,
                    secrets[6:4:-1],  # this range matches [5:7]
                )
            )

        gevent.joinall(greenlets, raise_error=True)

        msg = "All secrets must be registered, and they all must be registered only once"
        assert all(count[secret] == 1 for secret in secrets), msg
