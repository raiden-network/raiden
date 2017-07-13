import pytest

from raiden.tests.utils.blockchain import wait_until_block
from raiden.transfer.state import (
    CHANNEL_STATE_INITIALIZING,
    CHANNEL_STATE_OPENED,
)


@pytest.mark.timeout(120)
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('cached_genesis', [False])
@pytest.mark.parametrize('settle_timeout', [6])
def test_channel_lifecycle(raiden_network, tokens_addresses, settle_timeout):
    token = tokens_addresses[0]
    alice, bob = raiden_network

    alice_address = alice.raiden.address
    alice_deposit = 100
    alice_transfer = 60

    bob_address = bob.raiden.address
    bob_deposit = 50
    bob_transfer = 10

    wait_until_block(
        alice.raiden.chain,
        alice.raiden.chain.block_number() + 1,
    )

    channel = alice.raiden.api.open(
        token,
        bob_address,
    )

    while channel.state == CHANNEL_STATE_INITIALIZING:
        wait_until_block(
            alice.raiden.chain,
            alice.raiden.chain.block_number() + 1,
        )

    assert channel.state == CHANNEL_STATE_OPENED

    alice.raiden.api.deposit(
        token,
        bob_address,
        alice_deposit
    )

    bob.raiden.api.deposit(
        token,
        alice_address,
        bob_deposit
    )

    alice.raiden.api.transfer(
        token,
        alice_transfer,
        bob_address,
    )
    bob.raiden.api.transfer(
        token,
        bob_transfer,
        alice_address,
    )

    bob.raiden.api.close(
        token,
        alice_address
    )

    wait_until_block(
        bob.raiden.chain,
        bob.raiden.chain.block_number() + settle_timeout
    )
    alice.raiden.api.settle(
        token,
        bob_address
    )
