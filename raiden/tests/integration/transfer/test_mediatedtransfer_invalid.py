# -*- coding: utf-8 -*-
import pytest

from raiden.api.python import RaidenAPI2
from raiden.messages import (
    Lock,
    MediatedTransfer,
)
from raiden.tests.utils.blockchain import wait_until_block
from raiden.tests.utils.factories import (
    make_address,
    make_privkey_address,
    UNIT_HASHLOCK,
)
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import (
    assert_synched_channel_state,
    get_channelstate,
    mediated_transfer,
    sign_and_inject,
)


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_failsfast_mediatedtransfer_exceeding_distributable(
        raiden_network,
        token_addresses,
        deposit):

    app0, app1 = raiden_network
    token_address = token_addresses[0]

    result = app0.raiden.mediated_transfer_async(
        token_address,
        deposit * 2,
        app1.raiden.address,
        identifier=1,
    )

    assert result.successful()
    assert result.get_nowait() is False

    assert_synched_channel_state(
        token_address,
        app0, deposit, [],
        app1, deposit, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_failfast_mediatedtransfer_nochannel(raiden_network, token_addresses):
    """When the node has no channels it should fail without raising exceptions."""
    token_address = token_addresses[0]
    app0, app1 = raiden_network

    amount = 10
    async_result = app0.raiden.mediated_transfer_async(
        token_address,
        amount,
        app1.raiden.address,
        identifier=1,
    )
    assert async_result.wait() is False


@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_receive_mediatedtransfer_invalidnonce(
        raiden_network,
        deposit,
        token_addresses,
        reveal_timeout,
        network_wait):

    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    channel0 = get_channelstate(app0, app1, token_address)

    amount = 10
    mediated_transfer(
        app0,
        app2,
        token_address,
        amount,
        timeout=network_wait,
    )

    amount = 10
    identifier = 1
    repeated_nonce = 1
    expiration = reveal_timeout * 2
    mediated_transfer_message = MediatedTransfer(
        identifier=identifier,
        nonce=repeated_nonce,
        token=token_address,
        channel=channel0.identifier,
        transferred_amount=amount,
        recipient=app1.raiden.address,
        locksroot=UNIT_HASHLOCK,
        lock=Lock(amount, expiration, UNIT_HASHLOCK),
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

    assert_synched_channel_state(
        token_address,
        app0, deposit - amount, [],
        app1, deposit + amount, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_mediatedtransfer_invalidsender(
        raiden_network,
        token_addresses,
        deposit,
        reveal_timeout):

    app0, app1 = raiden_network
    token_address = token_addresses[0]
    other_key, other_address = make_privkey_address()

    channel0 = get_channelstate(app0, app1, token_address)
    amount = 10
    expiration = reveal_timeout * 2
    mediated_transfer_message = MediatedTransfer(
        identifier=1,
        nonce=1,
        token=token_address,
        channel=channel0.identifier,
        transferred_amount=0,
        recipient=app0.raiden.address,
        locksroot=UNIT_HASHLOCK,
        lock=Lock(amount, expiration, UNIT_HASHLOCK),
        target=app0.raiden.address,
        initiator=other_address,
        fee=0
    )

    sign_and_inject(
        mediated_transfer_message,
        other_key,
        other_address,
        app0,
    )

    assert_synched_channel_state(
        token_address,
        app0, deposit, [],
        app1, deposit, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_receive_mediatedtransfer_invalidrecipient(
        raiden_network,
        token_addresses,
        reveal_timeout,
        deposit):

    app0, app1 = raiden_network
    token_address = token_addresses[0]
    channel0 = get_channelstate(app0, app1, token_address)

    identifier = 1
    invalid_recipient = make_address()
    amount = 10
    expiration = reveal_timeout * 2
    mediated_transfer_message = MediatedTransfer(
        identifier=identifier,
        nonce=1,
        token=token_address,
        channel=channel0.identifier,
        transferred_amount=0,
        recipient=invalid_recipient,
        locksroot=UNIT_HASHLOCK,
        lock=Lock(amount, expiration, UNIT_HASHLOCK),
        target=app1.raiden.address,
        initiator=app0.raiden.address,
        fee=0
    )

    sign_and_inject(
        mediated_transfer_message,
        app0.raiden.private_key,
        app0.raiden.address,
        app1,
    )

    assert_synched_channel_state(
        token_address,
        app0, deposit, [],
        app1, deposit, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('settle_timeout', [30])
def test_received_mediatedtransfer_closedchannel(
        raiden_network,
        reveal_timeout,
        token_addresses,
        deposit):

    app0, app1 = raiden_network
    token_address = token_addresses[0]
    channel0 = get_channelstate(app0, app1, token_address)

    RaidenAPI2(app1.raiden).channel_close(
        token_address,
        app0.raiden.address,
    )

    wait_until_block(
        app0.raiden.chain,
        app0.raiden.chain.block_number() + 1,
    )

    # Now receive one mediated transfer for the closed channel
    amount = 10
    identifier = 1
    expiration = reveal_timeout * 2
    mediated_transfer_message = MediatedTransfer(
        identifier=identifier,
        nonce=1,
        token=token_address,
        channel=channel0.identifier,
        transferred_amount=0,
        recipient=app1.raiden.address,
        locksroot=UNIT_HASHLOCK,
        lock=Lock(amount, expiration, UNIT_HASHLOCK),
        target=app1.raiden.address,
        initiator=app0.raiden.address,
        fee=0
    )

    sign_and_inject(
        mediated_transfer_message,
        app0.raiden.private_key,
        app0.raiden.address,
        app1,
    )

    # The local state must not change since the channel is already closed
    assert_synched_channel_state(
        token_address,
        app0, deposit, [],
        app1, deposit, [],
    )
