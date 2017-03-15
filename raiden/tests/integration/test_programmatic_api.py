import pytest
import gevent

from raiden.tests.utils.blockchain import wait_until_block


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('cached_genesis', [False])
@pytest.mark.parametrize('settle_timeout', [5])
def test_channel_lifecycle(raiden_network, tokens_addresses):
    token = tokens_addresses[0].encode('hex')
    alice, bob = raiden_network

    alice_address = alice.raiden.address.encode('hex')
    alice_deposit = 100
    alice_transfer = 60

    bob_address = bob.raiden.address.encode('hex')
    bob_deposit = 50
    bob_transfer = 10

    alice.raiden.api.open(
        token,
        bob_address,
    )

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
        bob_address,
        alice_transfer
    )
    bob.raiden.api.transfer(
        token,
        alice_address,
        bob_transfer
    )

    bob.raiden.api.close(
        token,
        alice_address
    )

    wait_until_block(
        bob.raiden.chain,
        bob.raiden.chain.block_number() + 5
    )
    alice.raiden.api.settle(
        token,
        bob_address
    )
