from collections import defaultdict

import gevent
import pytest
from eth_utils import keccak

from raiden.constants import STATE_PRUNING_AFTER_BLOCKS
from raiden.exceptions import NoStateForBlockIdentifier
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.events import must_have_event
from raiden.tests.utils.factories import make_secret


def secret_registry_batch_happy_path(secret_registry_proxy, block_identifier):
    secrets = [make_secret() for i in range(4)]
    secrethashes = [keccak(secret) for secret in secrets]

    secret_registered_filter = secret_registry_proxy.secret_registered_filter()
    secret_registry_proxy.register_secret_batch(
        secrets=secrets,
        given_block_identifier=block_identifier,
    )

    logs = [
        secret_registry_proxy.proxy.decode_event(log)
        for log in secret_registered_filter.get_all_entries()
    ]

    for secrethash in secrethashes:
        secret_registered = must_have_event(
            logs,
            {
                'event': 'SecretRevealed',
                'args': {
                    'secrethash': secrethash,
                },
            },
        )
        assert secret_registered, 'All secrets from the batch must be registered'

        block = secret_registry_proxy.get_secret_registration_block_by_secrethash(
            secrethash=secrethash,
            block_identifier='latest',
        )
        msg = 'Block number reported by the proxy and the event must match'
        assert block == secret_registered['blockNumber'], msg


def test_register_secret_happy_path(secret_registry_proxy: SecretRegistry, contract_manager):
    """Test happy path of SecretRegistry with a single secret.

    Test that `register_secret` changes the smart contract state by registering
    the secret, this can be verified by the block height and the existence of
    the SecretRegistered event.
    """
    secret = make_secret()
    secrethash = keccak(secret)
    secret_unregistered = make_secret()
    secrethash_unregistered = keccak(secret_unregistered)

    secret_registered_filter = secret_registry_proxy.secret_registered_filter()

    assert not secret_registry_proxy.is_secret_registered(
        secrethash=secrethash,
        block_identifier='latest',
    ), 'Test setup is invalid, secret must be unknown'
    assert not secret_registry_proxy.is_secret_registered(
        secrethash=secrethash_unregistered,
        block_identifier='latest',
    ), 'Test setup is invalid, secret must be unknown'

    chain = BlockChainService(
        jsonrpc_client=secret_registry_proxy.client,
        contract_manager=contract_manager,
    )
    chain.wait_until_block(STATE_PRUNING_AFTER_BLOCKS + 1)

    with pytest.raises(NoStateForBlockIdentifier):
        secret_registry_proxy.is_secret_registered(
            secrethash=secrethash_unregistered,
            block_identifier=0,
        )

    secret_registry_proxy.register_secret(
        secret=secret,
        given_block_identifier='latest',
    )

    logs = [
        secret_registry_proxy.proxy.decode_event(encoded_log)
        for encoded_log in secret_registered_filter.get_all_entries()
    ]
    secret_registered = must_have_event(
        logs,
        {
            'event': 'SecretRevealed',
            'args': {
                'secrethash': secrethash,
            },
        },
    )

    msg = 'SecretRegistry.register_secret returned but the SecretRevealed event was not emitted.'
    assert secret_registered, msg

    registered_block = secret_registry_proxy.get_secret_registration_block_by_secrethash(
        secrethash=secrethash,
        block_identifier='latest',
    )
    msg = (
        'Block height returned by the SecretRegistry.get_secret_registration_block_by_secrethash '
        'does not match the block from the SecretRevealed event.'
    )
    assert secret_registered['blockNumber'] == registered_block, msg

    block = secret_registry_proxy.get_secret_registration_block_by_secrethash(
        secrethash=secrethash_unregistered,
        block_identifier='latest',
    )
    assert block is None, 'The secret that was not registered must not change block height!'


def test_register_secret_batch_happy_path(secret_registry_proxy):
    """Test happy path for secret registration batching."""
    secret_registry_batch_happy_path(secret_registry_proxy, 'latest')


def test_register_secret_batch_with_pruned_block(
        secret_registry_proxy,
        web3,
        private_keys,
        contract_manager,
):
    """Test secret registration with a pruned given block."""
    c1_client = JSONRPCClient(web3, private_keys[1])
    c1_chain = BlockChainService(
        jsonrpc_client=c1_client,
        contract_manager=contract_manager,
    )
    # Now wait until this block becomes pruned
    pruned_number = c1_chain.block_number()
    c1_chain.wait_until_block(target_block_number=pruned_number + STATE_PRUNING_AFTER_BLOCKS)
    secret_registry_batch_happy_path(secret_registry_proxy, pruned_number)


def test_concurrent_secret_registration(secret_registry_proxy, monkeypatch):
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
        count = defaultdict(int)
        transact = secret_registry_proxy.proxy.transact

        # Using positional arguments with the signature used by SecretRegistry
        # to call the ContractProxy in order to have access to the secret.
        # Monkey patching the proxy function because the test must registered
        # the data that is effectively sent with the transaction.
        def count_transactions(function_name, startgas, secrets):
            for secret in secrets:
                count[secret] += 1
                msg = (
                    'All secrets must be registered, '
                    'and they all must be registered only once'
                )
                assert count[secret] == 1, msg

            return transact(
                function_name,
                startgas,
                secrets,
            )

        m.setattr(
            secret_registry_proxy.proxy,
            'transact',
            count_transactions,
        )

        # Important: Make sure all secrets are actually used
        secrets = [
            make_secret()
            for _ in range(7)
        ]
        greenlets = set()

        # `register_secret` called twice
        for _ in range(2):
            greenlets.add(gevent.spawn(
                secret_registry_proxy.register_secret,
                secrets[0],
                'latest',
            ))

        # `register_secret_batch` called twice
        for _ in range(2):
            greenlets.add(gevent.spawn(
                secret_registry_proxy.register_secret_batch,
                secrets[1:3],
                'latest',
            ))

        # Calling `register_secret` then `register_secret_batch`
        # Calling `register_secret_batch` then `register_secret`
        for _ in range(2):
            greenlets.add(gevent.spawn(
                secret_registry_proxy.register_secret,
                secrets[3],
                'latest',
            ))
            greenlets.add(gevent.spawn(
                secret_registry_proxy.register_secret_batch,
                secrets[3:5],
                'latest',
            ))
            greenlets.add(gevent.spawn(
                secret_registry_proxy.register_secret,
                secrets[4],
                'latest',
            ))

        # `register_secret_batch` called twice, with different order of the
        # secret
        for _ in range(2):
            greenlets.add(gevent.spawn(
                secret_registry_proxy.register_secret_batch,
                secrets[5:7],
                'latest',
            ))
            greenlets.add(gevent.spawn(
                secret_registry_proxy.register_secret_batch,
                secrets[6:4:-1],  # this range matches [5:7]
                'latest',
            ))

        gevent.joinall(greenlets, raise_error=True)

        msg = (
            'All secrets must be registered, '
            'and they all must be registered only once'
        )
        assert all(count[secret] == 1 for secret in secrets), msg
