from hashlib import sha256

import gevent
import pytest

from raiden import waiting
from raiden.app import App
from raiden.constants import RoutingMode
from raiden.message_handler import MessageHandler
from raiden.network.transport import MatrixTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import raiden_events_search_for_item
from raiden.tests.utils.factories import make_secret
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import assert_synced_channel_state, watch_for_unlock_failures
from raiden.transfer import views
from raiden.transfer.events import EventPaymentSentSuccess
from raiden.transfer.mediated_transfer.events import SendLockedTransfer, SendSecretReveal
from raiden.utils import BlockNumber, create_default_identifier
from raiden.utils.typing import TokenAmount


@pytest.mark.parametrize("deposit", [10])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.skip("Issue: #4312")
def test_send_queued_messages(  # pylint: disable=unused-argument
    raiden_network, deposit, token_addresses, network_wait
):
    """Test re-sending of undelivered messages on node restart"""
    raise_on_failure(
        raiden_network,
        run_test_send_queued_messages,
        raiden_network=raiden_network,
        deposit=deposit,
        token_addresses=token_addresses,
        network_wait=network_wait,
    )


def run_test_send_queued_messages(raiden_network, deposit, token_addresses, network_wait):
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    number_of_transfers = 7
    amount_per_transfer = 1
    total_transferred_amount = amount_per_transfer * number_of_transfers

    # Make sure none of the transfers will be sent before the restart
    transfers = []
    for secret_seed in range(number_of_transfers):
        secret = make_secret(secret_seed)
        secrethash = sha256(secret).digest()
        transfers.append((create_default_identifier(), amount_per_transfer, secret, secrethash))

        app0.raiden.raiden_event_handler.hold(
            SendLockedTransfer, {"transfer": {"lock": {"secrethash": secrethash}}}
        )

    for identifier, amount, secret, _ in transfers:
        app0.raiden.mediated_transfer_async(
            token_network_address=token_network_address,
            amount=amount,
            target=app1.raiden.address,
            identifier=identifier,
            secret=secret,
        )

    app0.stop()

    # Restart the app. The pending transfers must be processed.
    new_transport = MatrixTransport(app0.raiden.config["transport"]["matrix"])
    raiden_event_handler = RaidenEventHandler()
    message_handler = MessageHandler()
    app0_restart = App(
        config=app0.config,
        chain=app0.raiden.chain,
        query_start_block=0,
        default_registry=app0.raiden.default_registry,
        default_secret_registry=app0.raiden.default_secret_registry,
        default_service_registry=app0.raiden.default_service_registry,
        default_one_to_n_address=app0.raiden.default_one_to_n_address,
        default_msc_address=app0.raiden.default_msc_address,
        transport=new_transport,
        raiden_event_handler=raiden_event_handler,
        message_handler=message_handler,
        routing_mode=RoutingMode.PRIVATE,
    )

    del app0
    app0_restart.start()

    # XXX: There is no synchronization among the app and the test, so it is
    # possible between `start` and the check bellow that some of the transfers
    # have completed, making it flaky.
    #
    # Make sure the transfers are in the queue and fail otherwise.
    # chain_state = views.state_from_raiden(app0_restart.raiden)
    # for _, _, _, secrethash in transfers:
    #     msg = "The secrethashes of the pending transfers must be in the queue after a restart."
    #     assert secrethash in chain_state.payment_mapping.secrethashes_to_task, msg

    with watch_for_unlock_failures(*raiden_network):
        exception = RuntimeError("Timeout while waiting for balance update for app0")
        with gevent.Timeout(20, exception=exception):
            waiting.wait_for_payment_balance(
                raiden=app0_restart.raiden,
                token_network_registry_address=token_network_registry_address,
                token_address=token_address,
                partner_address=app1.raiden.address,
                target_address=app1.raiden.address,
                target_balance=total_transferred_amount,
                retry_timeout=network_wait,
            )
        exception = RuntimeError("Timeout while waiting for balance update for app1")
        with gevent.Timeout(20, exception=exception):
            waiting.wait_for_payment_balance(
                raiden=app1.raiden,
                token_network_registry_address=token_network_registry_address,
                token_address=token_address,
                partner_address=app0_restart.raiden.address,
                target_address=app1.raiden.address,
                target_balance=total_transferred_amount,
                retry_timeout=network_wait,
            )

    assert_synced_channel_state(
        token_network_address,
        app0_restart,
        deposit - total_transferred_amount,
        [],
        app1,
        deposit + total_transferred_amount,
        [],
    )
    new_transport.stop()


@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
@pytest.mark.parametrize("number_of_tokens", [1])
def test_payment_statuses_are_restored(  # pylint: disable=unused-argument
    raiden_network, token_addresses, network_wait
):
    """ Test that when the Raiden is restarted, the dictionary of
    `targets_to_identifiers_to_statuses` is populated before the transport
    is started.
    This should happen because if a client gets restarted during a transfer
    cycle, once restarted, the client will proceed with the cycle
    until the transfer is successfully sent. However, the dictionary
    `targets_to_identifiers_to_statuses` will not contain the payment
    identifiers that were originally registered when the previous client
    started the transfers.
    Related issue: https://github.com/raiden-network/raiden/issues/3432
    """
    raise_on_failure(
        raiden_network,
        run_test_payment_statuses_are_restored,
        raiden_network=raiden_network,
        token_addresses=token_addresses,
        network_wait=network_wait,
    )


def run_test_payment_statuses_are_restored(raiden_network, token_addresses, network_wait):
    app0, app1 = raiden_network

    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    # make a few transfers from app0 to app1
    amount = 1
    spent_amount = TokenAmount(7)

    for identifier in range(spent_amount):
        # Make sure the transfer is not completed
        secret = make_secret(identifier)
        app0.raiden.raiden_event_handler.hold(SendSecretReveal, {"secret": secret})

        identifier = identifier + 1
        payment_status = app0.raiden.mediated_transfer_async(
            token_network_address=token_network_address,
            amount=amount,
            target=app1.raiden.address,
            identifier=identifier,
            secret=secret,
        )
        assert payment_status.payment_identifier == identifier

    app0_restart = App(
        config=app0.config,
        chain=app0.raiden.chain,
        query_start_block=BlockNumber(0),
        default_registry=app0.raiden.default_registry,
        default_secret_registry=app0.raiden.default_secret_registry,
        default_service_registry=app0.raiden.default_service_registry,
        default_one_to_n_address=app0.raiden.default_one_to_n_address,
        default_msc_address=app0.raiden.default_msc_address,
        transport=MatrixTransport(app0.raiden.config["transport"]["matrix"]),
        raiden_event_handler=RaidenEventHandler(),
        message_handler=MessageHandler(),
        routing_mode=RoutingMode.PRIVATE,
    )
    app0.stop()
    del app0  # from here on the app0_restart should be used
    # stop app1 to make sure that we don't complete the transfers before our checks
    app1.stop()
    app0_restart.start()

    # Check that the payment statuses were restored properly after restart
    for identifier in range(spent_amount):
        identifier = identifier + 1
        mapping = app0_restart.raiden.targets_to_identifiers_to_statuses
        status = mapping[app1.raiden.address][identifier]
        assert status.amount == 1
        assert status.payment_identifier == identifier
        assert status.token_network_address == token_network_address

    app1.start()  # now that our checks are done start app1 again
    waiting.wait_for_healthy(app0_restart.raiden, app1.raiden.address, network_wait)

    waiting.wait_for_payment_balance(
        raiden=app1.raiden,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
        partner_address=app0_restart.raiden.address,
        target_address=app1.raiden.address,
        target_balance=spent_amount,
        retry_timeout=network_wait,
    )

    # Check that payments are completed after both nodes come online after restart
    for identifier in range(spent_amount):
        assert raiden_events_search_for_item(
            app0_restart.raiden,
            EventPaymentSentSuccess,
            {"identifier": identifier + 1, "amount": 1},
        )
