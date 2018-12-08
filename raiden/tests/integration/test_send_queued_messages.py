import gevent
import pytest

from raiden import waiting
from raiden.app import App
from raiden.message_handler import MessageHandler
from raiden.network.transport import MatrixTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.protocol import dont_handle_node_change_network_state
from raiden.tests.utils.transfer import assert_synced_channel_state
from raiden.transfer import views


@pytest.mark.parametrize('deposit', [10])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_send_queued_messages(
        raiden_network,
        number_of_nodes,
        deposit,
        token_addresses,
        network_wait,
        skip_if_not_matrix,
):
    """Test re-sending of undelivered messages on node restart"""
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    with dont_handle_node_change_network_state():
        # stop app1 - transfer must be left unconfirmed
        app1.stop()

        # make a few transfers from app0 to app1
        amount = 1
        spent_amount = 7
        identifier = 1
        for _ in range(spent_amount):
            app0.raiden.mediated_transfer_async(
                token_network_identifier=token_network_identifier,
                amount=amount,
                target=app1.raiden.address,
                identifier=identifier,
            )
            identifier += 1

    # restart app0
    app0.raiden.stop()

    new_transport = MatrixTransport(
        app0.raiden.config['transport']['matrix'],
    )

    raiden_event_handler = RaidenEventHandler()
    message_handler = MessageHandler()

    app0_restart = App(
        config=app0.config,
        chain=app0.raiden.chain,
        query_start_block=0,
        default_registry=app0.raiden.default_registry,
        default_secret_registry=app0.raiden.default_secret_registry,
        transport=new_transport,
        raiden_event_handler=raiden_event_handler,
        message_handler=message_handler,
        discovery=app0.raiden.discovery,
    )

    app0.stop()
    del app0  # from here on the app0_restart should be used
    app1.start()

    app0_restart.start()

    waiting.wait_for_healthy(
        app0_restart.raiden,
        app1.raiden.address,
        network_wait,
    )
    waiting.wait_for_healthy(
        app1.raiden,
        app0_restart.raiden.address,
        network_wait,
    )

    exception = RuntimeError('Timeout while waiting for new channel')
    with gevent.Timeout(5, exception=exception):
        waiting.wait_for_newchannel(
            raiden=app0_restart.raiden,
            payment_network_id=payment_network_id,
            token_address=token_address,
            partner_address=app1.raiden.address,
            retry_timeout=network_wait,
        )
    exception = RuntimeError('Timeout while waiting for balance update for app0')
    with gevent.Timeout(30, exception=exception):
        waiting.wait_for_payment_balance(
            raiden=app0_restart.raiden,
            payment_network_id=payment_network_id,
            token_address=token_address,
            partner_address=app1.raiden.address,
            target_address=app1.raiden.address,
            target_balance=spent_amount,
            retry_timeout=network_wait,
        )

    waiting.wait_for_payment_balance(
        raiden=app1.raiden,
        payment_network_id=payment_network_id,
        token_address=token_address,
        partner_address=app0_restart.raiden.address,
        target_address=app1.raiden.address,
        target_balance=spent_amount,
        retry_timeout=network_wait,
    )

    assert_synced_channel_state(
        token_network_identifier,
        app0_restart, deposit - spent_amount, [],
        app1, deposit + spent_amount, [],
    )
