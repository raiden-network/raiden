import gevent
import pytest

from raiden.exceptions import RaidenUnrecoverableError
from raiden.message_handler import MessageHandler
from raiden.messages import LockedTransfer, RevealSecret
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.factories import UNIT_TRANSFER_INITIATOR, make_signed_transfer
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import assert_synced_channel_state, mediated_transfer, wait_assert
from raiden.transfer import views
from raiden.transfer.mediated_transfer.state_change import ActionInitMediator, ActionInitTarget
from raiden.utils import sha3


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_mediated_transfer(
        raiden_network,
        number_of_nodes,
        deposit,
        token_addresses,
        network_wait,
        public_and_private_rooms,
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    amount = 10
    mediated_transfer(
        app0,
        app2,
        token_network_identifier,
        amount,
        timeout=network_wait * number_of_nodes,
    )

    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app0, deposit - amount, [],
            app1, deposit + amount, [],
        )
    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app1, deposit - amount, [],
            app2, deposit + amount, [],
        )


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [1])
def test_locked_transfer_secret_registered_onchain(
        raiden_network,
        token_addresses,
        secret_registry_address,
):
    app0 = raiden_network[0]
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    amount = 1
    target = UNIT_TRANSFER_INITIATOR
    identifier = 1
    transfer_secret = sha3(target + b'1')

    secret_registry_proxy = app0.raiden.chain.secret_registry(
        secret_registry_address,
    )
    secret_registry_proxy.register_secret(transfer_secret)

    # Test that sending a transfer with a secret already registered on-chain fails
    with pytest.raises(RaidenUnrecoverableError):
        app0.raiden.start_mediated_transfer_with_secret(
            token_network_identifier,
            amount,
            target,
            identifier,
            transfer_secret,
        )

    expiration = 9999
    transfer = make_signed_transfer(
        amount,
        UNIT_TRANSFER_INITIATOR,
        app0.raiden.address,
        expiration,
        transfer_secret,
    )

    message_handler = MessageHandler()
    message_handler.handle_message_lockedtransfer(
        app0.raiden,
        transfer,
    )

    state_changes = app0.raiden.wal.storage.get_statechanges_by_identifier(0, 'latest')
    transfer_statechange_dispatched = (
        must_contain_entry(state_changes, ActionInitMediator, {}) or
        must_contain_entry(state_changes, ActionInitTarget, {})
    )
    assert not transfer_statechange_dispatched


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_mediated_transfer_with_entire_deposit(
        raiden_network,
        number_of_nodes,
        token_addresses,
        deposit,
        network_wait,
        public_and_private_rooms,
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )
    mediated_transfer(
        app0,
        app2,
        token_network_identifier,
        deposit,
        timeout=network_wait * number_of_nodes,
    )

    mediated_transfer(
        app2,
        app0,
        token_network_identifier,
        deposit * 2,
        timeout=network_wait * number_of_nodes,
    )

    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app0, deposit * 2, [],
            app1, 0, [],
        )
    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app1, deposit * 2, [],
            app2, 0, [],
        )


class _patch_transport:
    def __init__(self, transport_patched):
        self.patched = transport_patched
        self.patched._receive_message_unpatched = self.patched._receive_message
        self.patched._receive_message = lambda msg: self._receive_message(msg)
        self.done = False
        self.message = None

    def _receive_message(self, message):
        if not self.done and self.message is None and isinstance(message, LockedTransfer):
            self.message = message
            return
        self.patched._receive_message_unpatched(message)
        if not self.done and self.message is not None and isinstance(message, RevealSecret):
            self.patched._receive_message(self.message)
            self.done = True


@pytest.mark.skip(reason='Currently fails on travis')
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_mediated_transfer_messages_out_of_order(
        raiden_network,
        number_of_nodes,
        deposit,
        token_addresses,
        network_wait,
        skip_if_not_matrix,
):
    app0, app1, app2 = raiden_network
    _patch_transport(app1.raiden.transport)
    _patch_transport(app2.raiden.transport)
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    amount = 10
    mediated_transfer(
        app0,
        app2,
        token_network_identifier,
        amount,
        timeout=network_wait * number_of_nodes,
    )

    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app0, deposit - amount, [],
            app1, deposit + amount, [],
        )
    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app1, deposit - amount, [],
            app2, deposit + amount, [],
        )
