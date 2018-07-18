import random

import pytest

from raiden.api.python import RaidenAPI
from raiden.constants import UINT64_MAX
from raiden.messages import (
    Lock,
    LockedTransfer,
)
from raiden.tests.utils.geth import wait_until_block
from raiden.tests.utils.factories import (
    make_address,
    make_privkey_address,
    UNIT_CHAIN_ID,
    UNIT_SECRETHASH,
)
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import (
    assert_synched_channel_state,
    wait_assert,
    get_channelstate,
    mediated_transfer,
    sign_and_inject,
)
from raiden.transfer import views


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_failsfast_lockedtransfer_exceeding_distributable(
        raiden_network,
        token_addresses,
        deposit,
):

    app0, app1 = raiden_network
    token_address = token_addresses[0]

    payment_network_identifier = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        payment_network_identifier,
        token_address,
    )
    result = app0.raiden.mediated_transfer_async(
        token_network_identifier,
        deposit * 2,
        app1.raiden.address,
        identifier=1,
    )

    assert result.successful()
    assert result.get_nowait() is False

    assert_synched_channel_state(
        token_network_identifier,
        app0, deposit, [],
        app1, deposit, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_failfast_lockedtransfer_nochannel(raiden_network, token_addresses):
    """When the node has no channels it should fail without raising exceptions."""
    token_address = token_addresses[0]
    app0, app1 = raiden_network

    amount = 10
    payment_network_identifier = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        payment_network_identifier,
        token_address,
    )
    async_result = app0.raiden.mediated_transfer_async(
        token_network_identifier,
        amount,
        app1.raiden.address,
        identifier=1,
    )
    assert async_result.wait() is False


@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_receive_lockedtransfer_invalidnonce(
        raiden_network,
        number_of_nodes,
        deposit,
        token_addresses,
        reveal_timeout,
        network_wait,
):

    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )
    channel0 = get_channelstate(app0, app1, token_network_identifier)

    amount = 10
    mediated_transfer(
        app0,
        app2,
        token_network_identifier,
        amount,
        timeout=network_wait * number_of_nodes,
    )

    amount = 10
    payment_identifier = 1
    repeated_nonce = 1
    expiration = reveal_timeout * 2
    mediated_transfer_message = LockedTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=payment_identifier,
        nonce=repeated_nonce,
        token_network_address=token_network_identifier,
        token=token_address,
        channel_identifier=channel0.identifier,
        transferred_amount=amount,
        locked_amount=amount,
        recipient=app1.raiden.address,
        locksroot=UNIT_SECRETHASH,
        lock=Lock(amount, expiration, UNIT_SECRETHASH),
        target=app2.raiden.address,
        initiator=app0.raiden.address,
        fee=0,
    )

    sign_and_inject(
        mediated_transfer_message,
        app0.raiden.private_key,
        app0.raiden.address,
        app1,
    )

    wait_assert(
        token_network_identifier,
        app0, deposit - amount, [],
        app1, deposit + amount, [],
        func=assert_synched_channel_state,
        timeout=network_wait,
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_lockedtransfer_invalidsender(
        raiden_network,
        token_addresses,
        deposit,
        reveal_timeout,
):

    app0, app1 = raiden_network
    token_address = token_addresses[0]
    other_key, other_address = make_privkey_address()

    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )
    channel0 = get_channelstate(app0, app1, token_network_identifier)
    lock_amount = 10
    expiration = reveal_timeout * 2
    mediated_transfer_message = LockedTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=1,
        nonce=1,
        token_network_address=token_network_identifier,
        token=token_address,
        channel_identifier=channel0.identifier,
        transferred_amount=0,
        locked_amount=lock_amount,
        recipient=app0.raiden.address,
        locksroot=UNIT_SECRETHASH,
        lock=Lock(lock_amount, expiration, UNIT_SECRETHASH),
        target=app0.raiden.address,
        initiator=other_address,
        fee=0,
    )

    sign_and_inject(
        mediated_transfer_message,
        other_key,
        other_address,
        app0,
    )

    assert_synched_channel_state(
        token_network_identifier,
        app0, deposit, [],
        app1, deposit, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_receive_lockedtransfer_invalidrecipient(
        raiden_network,
        token_addresses,
        reveal_timeout,
        deposit,
):

    app0, app1 = raiden_network
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )
    channel0 = get_channelstate(app0, app1, token_network_identifier)

    payment_identifier = 1
    invalid_recipient = make_address()
    lock_amount = 10
    expiration = reveal_timeout * 2
    mediated_transfer_message = LockedTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=payment_identifier,
        nonce=1,
        token_network_address=token_network_identifier,
        token=token_address,
        channel_identifier=channel0.identifier,
        transferred_amount=0,
        locked_amount=lock_amount,
        recipient=invalid_recipient,
        locksroot=UNIT_SECRETHASH,
        lock=Lock(lock_amount, expiration, UNIT_SECRETHASH),
        target=app1.raiden.address,
        initiator=app0.raiden.address,
        fee=0,
    )

    sign_and_inject(
        mediated_transfer_message,
        app0.raiden.private_key,
        app0.raiden.address,
        app1,
    )

    assert_synched_channel_state(
        token_network_identifier,
        app0, deposit, [],
        app1, deposit, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('settle_timeout', [30])
def test_received_lockedtransfer_closedchannel(
        raiden_network,
        reveal_timeout,
        token_addresses,
        deposit,
):

    app0, app1 = raiden_network
    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )
    channel0 = get_channelstate(app0, app1, token_network_identifier)

    RaidenAPI(app1.raiden).channel_close(
        registry_address,
        token_address,
        app0.raiden.address,
    )

    wait_until_block(
        app0.raiden.chain,
        app0.raiden.chain.block_number() + 1,
    )

    # Now receive one mediated transfer for the closed channel
    lock_amount = 10
    payment_identifier = 1
    expiration = reveal_timeout * 2
    mediated_transfer_message = LockedTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=payment_identifier,
        nonce=1,
        token_network_address=token_network_identifier,
        token=token_address,
        channel_identifier=channel0.identifier,
        transferred_amount=0,
        locked_amount=lock_amount,
        recipient=app1.raiden.address,
        locksroot=UNIT_SECRETHASH,
        lock=Lock(lock_amount, expiration, UNIT_SECRETHASH),
        target=app1.raiden.address,
        initiator=app0.raiden.address,
        fee=0,
    )

    sign_and_inject(
        mediated_transfer_message,
        app0.raiden.private_key,
        app0.raiden.address,
        app1,
    )

    # The local state must not change since the channel is already closed
    assert_synched_channel_state(
        token_network_identifier,
        app0, deposit, [],
        app1, deposit, [],
    )
