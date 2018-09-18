import gevent
import pytest

from raiden.messages import LockedTransfer, RevealSecret
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import assert_synced_channel_state, mediated_transfer, wait_assert
from raiden.transfer import views


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
