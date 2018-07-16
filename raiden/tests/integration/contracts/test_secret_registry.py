from eth_utils import keccak
from raiden.tests.utils import get_random_bytes
import pytest
import types
import gevent
from raiden.network.proxies import SecretRegistry


def test_secret_registry(secret_registry_proxy):
    #  register secret
    secret = get_random_bytes(32)
    event_filter = secret_registry_proxy.secret_registered_filter()
    secret_registry_proxy.register_secret(secret)

    # check if event is raised
    logs = event_filter.get_all_entries()
    assert len(logs) == 1
    decoded_event = secret_registry_proxy.proxy.decode_event(logs[0])
    data = keccak(secret)
    assert decoded_event['args']['secrethash'] == data
    # check if registration block matches
    block = secret_registry_proxy.get_register_block_for_secrethash(data)
    assert logs[0]['blockNumber'] == block

    #  test non-existing secret
    assert 0 == secret_registry_proxy.get_register_block_for_secrethash(b'\x11' * 32)


def test_secret_registry_register_batch(secret_registry_proxy):
    secrets = [get_random_bytes(32) for i in range(4)]
    secrethashes = [keccak(secret) for secret in secrets]

    event_filter = secret_registry_proxy.secret_registered_filter()
    secret_registry_proxy.register_secret_batch(secrets)

    logs = event_filter.get_all_entries()
    assert len(logs) == 4

    block = secret_registry_proxy.get_register_block_for_secrethash(secrethashes[0])
    decoded_events = [secret_registry_proxy.proxy.decode_event(log) for log in logs]
    assert all(event['blockNumber'] == block for event in decoded_events)

    recovered_hashes = [event['args']['secrethash'] for event in decoded_events]
    assert all(secrethash in recovered_hashes for secrethash in secrethashes)


@pytest.fixture
def secret_registry_proxy_patched(secret_registry_proxy):
    secret_registry_patched = SecretRegistry(
        secret_registry_proxy.client,
        secret_registry_proxy.address,
    )
    _register_secret_batch = secret_registry_patched._register_secret_batch

    def register_secret_batch_patched(self, secrets):
        """Make sure the transaction is sent only once per secret"""
        for secret in secrets:
            assert secret not in self.trigger
            self.trigger[secret] = True
        return _register_secret_batch(secrets)

    secret_registry_patched._register_secret_batch = types.MethodType(
        register_secret_batch_patched,
        secret_registry_patched,
    )
    secret_registry_patched.trigger = dict()
    return secret_registry_patched


def test_concurrent_access(
    secret_registry_proxy_patched,
):
    """Test if multiple greenlets actually send only one transaction
    when registering a secret.
    This is done by patchin secret_registry_proxy to forbid more than
    one call to `_register_secret_batch`.
    """
    secret = get_random_bytes(32)
    # Spawn multiple greenlets registrering a single secret
    # Patched secret registry asserts that the on-chain registry call
    # is only called once.
    events = [
        gevent.spawn(
            secret_registry_proxy_patched.register_secret,
            secret,
        )
        for _ in range(0, 40)
    ]
    gevent.joinall(events)
