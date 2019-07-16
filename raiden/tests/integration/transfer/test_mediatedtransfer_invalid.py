import random

import gevent
import pytest

from raiden.api.python import RaidenAPI
from raiden.constants import EMPTY_SIGNATURE, UINT64_MAX
from raiden.messages.metadata import Metadata, RouteMetadata
from raiden.messages.transfers import Lock, LockedTransfer
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.factories import (
    UNIT_CHAIN_ID,
    UNIT_SECRETHASH,
    make_address,
    make_privkey_address,
)
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import (
    assert_synced_channel_state,
    get_channelstate,
    sign_and_inject,
    transfer,
    wait_assert,
)
from raiden.transfer import views
from raiden.transfer.events import EventPaymentSentFailed
from raiden.utils.signer import LocalSigner


@pytest.mark.parametrize("channels_per_node", [1])
@pytest.mark.parametrize("number_of_nodes", [2])
def test_failsfast_lockedtransfer_exceeding_distributable(
    raiden_network, token_addresses, deposit
):
    raise_on_failure(
        raiden_network,
        run_test_failsfast_lockedtransfer_exceeding_distributable,
        raiden_network=raiden_network,
        token_addresses=token_addresses,
        deposit=deposit,
    )


def run_test_failsfast_lockedtransfer_exceeding_distributable(
    raiden_network, token_addresses, deposit
):

    app0, app1 = raiden_network
    token_address = token_addresses[0]

    payment_network_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), payment_network_address, token_address
    )
    payment_status = app0.raiden.mediated_transfer_async(
        token_network_address, deposit * 2, app1.raiden.address, identifier=1
    )

    assert isinstance(payment_status.payment_done.get(timeout=5), EventPaymentSentFailed)
    assert payment_status.payment_done.successful()

    assert_synced_channel_state(token_network_address, app0, deposit, [], app1, deposit, [])


@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [0])
def test_failfast_lockedtransfer_nochannel(raiden_network, token_addresses):
    raise_on_failure(
        raiden_network,
        run_test_failfast_lockedtransfer_nochannel,
        raiden_network=raiden_network,
        token_addresses=token_addresses,
    )


def run_test_failfast_lockedtransfer_nochannel(raiden_network, token_addresses):
    """When the node has no channels it should fail without raising exceptions."""
    token_address = token_addresses[0]
    app0, app1 = raiden_network

    amount = 10
    payment_network_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), payment_network_address, token_address
    )
    payment_status = app0.raiden.mediated_transfer_async(
        token_network_address, amount, app1.raiden.address, identifier=1
    )
    assert isinstance(payment_status.payment_done.get(), EventPaymentSentFailed)


@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
def test_receive_lockedtransfer_invalidnonce(
    raiden_network, number_of_nodes, deposit, token_addresses, reveal_timeout, network_wait
):
    raise_on_failure(
        raiden_network,
        run_test_receive_lockedtransfer_invalidnonce,
        raiden_network=raiden_network,
        number_of_nodes=number_of_nodes,
        deposit=deposit,
        token_addresses=token_addresses,
        reveal_timeout=reveal_timeout,
        network_wait=network_wait,
    )


def run_test_receive_lockedtransfer_invalidnonce(
    raiden_network, number_of_nodes, deposit, token_addresses, reveal_timeout, network_wait
):

    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), app0.raiden.default_registry.address, token_address
    )
    channel0 = get_channelstate(app0, app1, token_network_address)

    amount = 10
    transfer(
        initiator_app=app0,
        target_app=app2,
        token_address=token_address,
        amount=amount,
        identifier=1,
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
        token_network_address=token_network_address,
        token=token_address,
        channel_identifier=channel0.identifier,
        transferred_amount=amount,
        locked_amount=amount,
        recipient=app1.raiden.address,
        locksroot=UNIT_SECRETHASH,
        lock=Lock(amount=amount, expiration=expiration, secrethash=UNIT_SECRETHASH),
        target=app2.raiden.address,
        initiator=app0.raiden.address,
        fee=0,
        signature=EMPTY_SIGNATURE,
        metadata=Metadata(
            routes=[RouteMetadata(route=[app1.raiden.address, app2.raiden.address])]
        ),
    )

    sign_and_inject(mediated_transfer_message, app0.raiden.signer, app1)

    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app0,
            deposit - amount,
            [],
            app1,
            deposit + amount,
            [],
        )


@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
def test_receive_lockedtransfer_invalidsender(
    raiden_network, token_addresses, deposit, reveal_timeout
):
    raise_on_failure(
        raiden_network,
        run_test_receive_lockedtransfer_invalidsender,
        raiden_network=raiden_network,
        token_addresses=token_addresses,
        deposit=deposit,
        reveal_timeout=reveal_timeout,
    )


def run_test_receive_lockedtransfer_invalidsender(
    raiden_network, token_addresses, deposit, reveal_timeout
):

    app0, app1 = raiden_network
    token_address = token_addresses[0]
    other_key, other_address = make_privkey_address()

    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), app0.raiden.default_registry.address, token_address
    )
    channel0 = get_channelstate(app0, app1, token_network_address)
    lock_amount = 10
    expiration = reveal_timeout * 2
    mediated_transfer_message = LockedTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=1,
        nonce=1,
        token_network_address=token_network_address,
        token=token_address,
        channel_identifier=channel0.identifier,
        transferred_amount=0,
        locked_amount=lock_amount,
        recipient=app0.raiden.address,
        locksroot=UNIT_SECRETHASH,
        lock=Lock(amount=lock_amount, expiration=expiration, secrethash=UNIT_SECRETHASH),
        target=app0.raiden.address,
        initiator=other_address,
        fee=0,
        signature=EMPTY_SIGNATURE,
        metadata=Metadata(routes=[RouteMetadata(route=[app0.raiden.address])]),
    )

    sign_and_inject(mediated_transfer_message, LocalSigner(other_key), app0)

    assert_synced_channel_state(token_network_address, app0, deposit, [], app1, deposit, [])


@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
def test_receive_lockedtransfer_invalidrecipient(
    raiden_network, token_addresses, reveal_timeout, deposit
):
    raise_on_failure(
        raiden_network,
        run_test_receive_lockedtransfer_invalidrecipient,
        raiden_network=raiden_network,
        token_addresses=token_addresses,
        reveal_timeout=reveal_timeout,
        deposit=deposit,
    )


def run_test_receive_lockedtransfer_invalidrecipient(
    raiden_network, token_addresses, reveal_timeout, deposit
):

    app0, app1 = raiden_network
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), app0.raiden.default_registry.address, token_address
    )
    channel0 = get_channelstate(app0, app1, token_network_address)

    payment_identifier = 1
    invalid_recipient = make_address()
    lock_amount = 10
    expiration = reveal_timeout * 2
    mediated_transfer_message = LockedTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=payment_identifier,
        nonce=1,
        token_network_address=token_network_address,
        token=token_address,
        channel_identifier=channel0.identifier,
        transferred_amount=0,
        locked_amount=lock_amount,
        recipient=invalid_recipient,
        locksroot=UNIT_SECRETHASH,
        lock=Lock(amount=lock_amount, expiration=expiration, secrethash=UNIT_SECRETHASH),
        target=app1.raiden.address,
        initiator=app0.raiden.address,
        fee=0,
        signature=EMPTY_SIGNATURE,
        metadata=Metadata(routes=[RouteMetadata(route=[app1.raiden.address])]),
    )

    sign_and_inject(mediated_transfer_message, app0.raiden.signer, app1)

    assert_synced_channel_state(token_network_address, app0, deposit, [], app1, deposit, [])


@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
@pytest.mark.parametrize("settle_timeout", [30])
def test_received_lockedtransfer_closedchannel(
    raiden_network, reveal_timeout, token_addresses, deposit
):
    raise_on_failure(
        raiden_network,
        run_test_received_lockedtransfer_closedchannel,
        raiden_network=raiden_network,
        reveal_timeout=reveal_timeout,
        token_addresses=token_addresses,
        deposit=deposit,
    )


def run_test_received_lockedtransfer_closedchannel(
    raiden_network, reveal_timeout, token_addresses, deposit
):

    app0, app1 = raiden_network
    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), app0.raiden.default_registry.address, token_address
    )
    channel0 = get_channelstate(app0, app1, token_network_address)

    RaidenAPI(app1.raiden).channel_close(registry_address, token_address, app0.raiden.address)

    app0.raiden.chain.wait_until_block(target_block_number=app0.raiden.chain.block_number() + 1)

    # Now receive one mediated transfer for the closed channel
    lock_amount = 10
    payment_identifier = 1
    expiration = reveal_timeout * 2
    mediated_transfer_message = LockedTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=payment_identifier,
        nonce=1,
        token_network_address=token_network_address,
        token=token_address,
        channel_identifier=channel0.identifier,
        transferred_amount=0,
        locked_amount=lock_amount,
        recipient=app1.raiden.address,
        locksroot=UNIT_SECRETHASH,
        lock=Lock(amount=lock_amount, expiration=expiration, secrethash=UNIT_SECRETHASH),
        target=app1.raiden.address,
        initiator=app0.raiden.address,
        fee=0,
        signature=EMPTY_SIGNATURE,
        metadata=Metadata(routes=[RouteMetadata(route=[app1.raiden.address])]),
    )

    sign_and_inject(mediated_transfer_message, app0.raiden.signer, app1)

    # The local state must not change since the channel is already closed
    assert_synced_channel_state(token_network_address, app0, deposit, [], app1, deposit, [])
