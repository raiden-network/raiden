from hashlib import sha256
from typing import List
from unittest.mock import patch

import pytest

from raiden.app import App
from raiden.exceptions import RaidenUnrecoverableError
from raiden.message_handler import MessageHandler
from raiden.messages.transfers import LockedTransfer, RevealSecret, SecretRequest
from raiden.network.pathfinding import PFSConfig, PFSInfo
from raiden.routing import get_best_routes_internal
from raiden.settings import DEFAULT_MEDIATION_FEE_MARGIN, DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.storage.sqlite import RANGE_ALL_STATE_CHANGES
from raiden.tests.utils import factories
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.protocol import WaitForMessage
from raiden.tests.utils.transfer import (
    assert_succeeding_transfer_invariants,
    assert_synced_channel_state,
    block_timeout_for_transfer_by_secrethash,
    calculate_amount_to_drain_channel,
    transfer,
    transfer_and_assert_path,
    wait_assert,
)
from raiden.transfer import views
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.transfer.mediated_transfer.state_change import ActionInitMediator, ActionInitTarget
from raiden.transfer.state_change import ActionChannelUpdateFee
from raiden.utils import sha3
from raiden.utils.typing import BlockNumber, FeeAmount, PaymentAmount, TokenAmount
from raiden.waiting import wait_for_block


@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [3])
def test_mediated_transfer(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait
):
    raise_on_failure(
        raiden_network,
        run_test_mediated_transfer,
        raiden_network=raiden_network,
        number_of_nodes=number_of_nodes,
        deposit=deposit,
        token_addresses=token_addresses,
        network_wait=network_wait,
    )


def run_test_mediated_transfer(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    amount = 10
    secrethash = transfer(
        initiator_app=app0,
        target_app=app2,
        token_address=token_address,
        amount=amount,
        identifier=1,
        timeout=network_wait * number_of_nodes,
    )

    with block_timeout_for_transfer_by_secrethash(app1.raiden, secrethash):
        wait_assert(
            assert_succeeding_transfer_invariants,
            token_network_address,
            app0,
            deposit - amount,
            [],
            app1,
            deposit + amount,
            [],
        )
    with block_timeout_for_transfer_by_secrethash(app1.raiden, secrethash):
        wait_assert(
            assert_succeeding_transfer_invariants,
            token_network_address,
            app1,
            deposit - amount,
            [],
            app2,
            deposit + amount,
            [],
        )


@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [1])
def test_locked_transfer_secret_registered_onchain(
    raiden_network, token_addresses, secret_registry_address, retry_timeout
):
    raise_on_failure(
        raiden_network,
        run_test_locked_transfer_secret_registered_onchain,
        raiden_network=raiden_network,
        token_addresses=token_addresses,
        secret_registry_address=secret_registry_address,
        retry_timeout=retry_timeout,
    )


def run_test_locked_transfer_secret_registered_onchain(
    raiden_network, token_addresses, secret_registry_address, retry_timeout
):
    app0 = raiden_network[0]
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    amount = 1
    target = factories.UNIT_TRANSFER_INITIATOR
    identifier = 1
    transfer_secret = sha3(target + b"1")

    secret_registry_proxy = app0.raiden.chain.secret_registry(secret_registry_address)
    secret_registry_proxy.register_secret(secret=transfer_secret)

    # Wait until our node has processed the block that the secret registration was mined at
    block_number = app0.raiden.get_block_number()
    wait_for_block(
        raiden=app0.raiden,
        block_number=block_number + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
        retry_timeout=retry_timeout,
    )

    # Test that sending a transfer with a secret already registered on-chain fails
    with pytest.raises(RaidenUnrecoverableError):
        app0.raiden.start_mediated_transfer_with_secret(
            token_network_address=token_network_address,
            amount=amount,
            target=target,
            identifier=identifier,
            secret=transfer_secret,
        )

    # Test that receiving a transfer with a secret already registered on chain fails
    expiration = 9999
    locked_transfer = factories.create(
        factories.LockedTransferProperties(
            amount=amount,
            target=app0.raiden.address,
            expiration=expiration,
            secret=transfer_secret,
        )
    )

    message_handler = MessageHandler()
    message_handler.handle_message_lockedtransfer(app0.raiden, locked_transfer)

    state_changes = app0.raiden.wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)
    transfer_statechange_dispatched = search_for_item(
        state_changes, ActionInitMediator, {}
    ) or search_for_item(state_changes, ActionInitTarget, {})
    assert not transfer_statechange_dispatched


@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [3])
def test_mediated_transfer_with_entire_deposit(
    raiden_network, number_of_nodes, token_addresses, deposit, network_wait
):
    raise_on_failure(
        raiden_network,
        run_test_mediated_transfer_with_entire_deposit,
        raiden_network=raiden_network,
        number_of_nodes=number_of_nodes,
        token_addresses=token_addresses,
        deposit=deposit,
        network_wait=network_wait,
    )


def run_test_mediated_transfer_with_entire_deposit(
    raiden_network, number_of_nodes, token_addresses, deposit, network_wait
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    amount = calculate_amount_to_drain_channel(deposit)

    secrethash = transfer_and_assert_path(
        path=raiden_network,
        token_address=token_address,
        amount=amount,
        identifier=1,
        timeout=network_wait * number_of_nodes,
    )

    reverse_path = list(raiden_network[::-1])
    transfer_and_assert_path(
        path=reverse_path,
        token_address=token_address,
        amount=amount * 2,
        identifier=2,
        timeout=network_wait * number_of_nodes,
    )

    with block_timeout_for_transfer_by_secrethash(app1.raiden, secrethash):
        wait_assert(
            assert_succeeding_transfer_invariants,
            token_network_address,
            app0,
            deposit * 2,
            [],
            app1,
            0,
            [],
        )
    with block_timeout_for_transfer_by_secrethash(app2.raiden, secrethash):
        wait_assert(
            assert_succeeding_transfer_invariants,
            token_network_address,
            app1,
            deposit * 2,
            [],
            app2,
            0,
            [],
        )


@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [3])
def test_mediated_transfer_messages_out_of_order(  # pylint: disable=unused-argument
    raiden_network, deposit, token_addresses, network_wait
):
    raise_on_failure(
        raiden_network,
        run_test_mediated_transfer_messages_out_of_order,
        raiden_network=raiden_network,
        deposit=deposit,
        token_addresses=token_addresses,
        network_wait=network_wait,
    )


def run_test_mediated_transfer_messages_out_of_order(
    raiden_network, deposit, token_addresses, network_wait
):
    """Raiden must properly handle repeated locked transfer messages."""
    app0, app1, app2 = raiden_network

    app1_wait_for_message = WaitForMessage()
    app2_wait_for_message = WaitForMessage()

    app1.raiden.message_handler = app1_wait_for_message
    app2.raiden.message_handler = app2_wait_for_message

    secret = factories.make_secret(0)
    secrethash = sha256(secret).digest()

    # Save the messages, these will be processed again
    app1_mediatedtransfer = app1_wait_for_message.wait_for_message(
        LockedTransfer, {"lock": {"secrethash": secrethash}}
    )
    app2_mediatedtransfer = app2_wait_for_message.wait_for_message(
        LockedTransfer, {"lock": {"secrethash": secrethash}}
    )
    # Wait until the node receives a reveal secret to redispatch the locked
    # transfer message
    app1_revealsecret = app1_wait_for_message.wait_for_message(RevealSecret, {"secret": secret})
    app2_revealsecret = app2_wait_for_message.wait_for_message(RevealSecret, {"secret": secret})

    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    amount = 10
    identifier = 1
    transfer_received = app0.raiden.start_mediated_transfer_with_secret(
        token_network_address=token_network_address,
        amount=amount,
        target=app2.raiden.address,
        identifier=identifier,
        secret=secret,
    )

    # - Wait until reveal secret is received to replay the message
    # - The secret is revealed backwards, app2 should be first
    # - The locked transfer is sent before the secret reveal, so the mediated
    #   transfers async results must be set and `get_nowait` can be used
    app2_revealsecret.get(timeout=network_wait)
    mediated_transfer_msg = app2_mediatedtransfer.get_nowait()
    app2.raiden.message_handler.handle_message_lockedtransfer(app2.raiden, mediated_transfer_msg)

    app1_revealsecret.get(timeout=network_wait)
    app1.raiden.message_handler.handle_message_lockedtransfer(
        app1.raiden, app1_mediatedtransfer.get_nowait()
    )

    transfer_received.payment_done.wait()
    with block_timeout_for_transfer_by_secrethash(app1.raiden, secrethash):
        wait_assert(
            assert_succeeding_transfer_invariants,
            token_network_address,
            app0,
            deposit - amount,
            [],
            app1,
            deposit + amount,
            [],
        )

    with block_timeout_for_transfer_by_secrethash(app2.raiden, secrethash):
        wait_assert(
            assert_succeeding_transfer_invariants,
            token_network_address,
            app1,
            deposit - amount,
            [],
            app2,
            deposit + amount,
            [],
        )


@pytest.mark.parametrize("number_of_nodes", (1,))
@pytest.mark.parametrize("channels_per_node", (CHAIN,))
def test_mediated_transfer_calls_pfs(raiden_network, token_addresses):
    raise_on_failure(
        raiden_network,
        run_test_mediated_transfer_calls_pfs,
        raiden_network=raiden_network,
        token_addresses=token_addresses,
    )


def run_test_mediated_transfer_calls_pfs(raiden_network, token_addresses):
    app0, = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    with patch("raiden.routing.query_paths", return_value=([], None)) as patched:

        app0.raiden.start_mediated_transfer_with_secret(
            token_network_address=token_network_address,
            amount=10,
            target=factories.HOP1,
            identifier=1,
            secret=b"1" * 32,
        )
        assert not patched.called

        # Setup PFS config
        app0.raiden.config["pfs_config"] = PFSConfig(
            info=PFSInfo(
                url="mock-address",
                chain_id=app0.raiden.chain.network_id,
                token_network_registry_address=token_network_registry_address,
                payment_address=factories.make_address(),
                message="",
                operator="",
                version="",
                price=TokenAmount(0),
            ),
            maximum_fee=TokenAmount(100),
            iou_timeout=BlockNumber(100),
            max_paths=5,
        )

        app0.raiden.start_mediated_transfer_with_secret(
            token_network_address=token_network_address,
            amount=11,
            target=factories.HOP2,
            identifier=2,
            secret=b"2" * 32,
        )
        assert patched.call_count == 1

        # Mediator should not re-query PFS
        locked_transfer = factories.create(
            factories.LockedTransferProperties(
                amount=TokenAmount(5),
                initiator=factories.HOP1,
                target=factories.HOP2,
                sender=factories.HOP1,
                pkey=factories.HOP1_KEY,
                token=token_address,
                canonical_identifier=factories.make_canonical_identifier(
                    token_network_address=token_network_address
                ),
            )
        )
        app0.raiden.mediate_mediated_transfer(locked_transfer)
        assert patched.call_count == 1


# pylint: disable=unused-argument
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [3])
def test_mediated_transfer_with_node_consuming_more_than_allocated_fee(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait
):
    """
    Tests a mediator node consuming more fees than allocated.
    Which means that the initiator will not reveal the secret
    to the target.
    """
    raise_on_failure(
        raiden_network,
        run_test_mediated_transfer_with_node_consuming_more_than_allocated_fee,
        raiden_network=raiden_network,
        number_of_nodes=number_of_nodes,
        deposit=deposit,
        token_addresses=token_addresses,
        network_wait=network_wait,
    )


def run_test_mediated_transfer_with_node_consuming_more_than_allocated_fee(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )
    fee = FeeAmount(5)
    amount = PaymentAmount(100)

    app1_app2_channel_state = views.get_channelstate_by_token_network_and_partner(
        chain_state=views.state_from_raiden(app1.raiden),
        token_network_address=token_network_address,
        partner_address=app2.raiden.address,
    )

    # Let app1 consume all of the allocated mediation fee
    action_update_fee = ActionChannelUpdateFee(
        canonical_identifier=app1_app2_channel_state.canonical_identifier,
        fee_schedule=FeeScheduleState(flat=FeeAmount(fee * 2)),
    )

    app1.raiden.handle_state_changes(state_changes=[action_update_fee])

    secret = factories.make_secret(0)
    secrethash = sha256(secret).digest()

    wait_message_handler = WaitForMessage()
    app0.raiden.message_handler = wait_message_handler
    secret_request_received = wait_message_handler.wait_for_message(
        SecretRequest, {"secrethash": secrethash}
    )

    def get_best_routes_with_fees(*args, **kwargs):
        routes = get_best_routes_internal(*args, **kwargs)
        for r in routes:
            r.estimated_fee = fee
        return routes

    with patch("raiden.routing.get_best_routes_internal", get_best_routes_with_fees):
        app0.raiden.start_mediated_transfer_with_secret(
            token_network_address=token_network_address,
            amount=amount,
            target=app2.raiden.address,
            identifier=1,
            secret=secret,
        )

    app0_app1_channel_state = views.get_channelstate_by_token_network_and_partner(
        chain_state=views.state_from_raiden(app0.raiden),
        token_network_address=token_network_address,
        partner_address=app1.raiden.address,
    )

    msg = "App0 should have the transfer in secrethashes_to_lockedlocks"
    assert secrethash in app0_app1_channel_state.our_state.secrethashes_to_lockedlocks, msg

    msg = "App0 should have locked the amount + fee"
    lock_amount = app0_app1_channel_state.our_state.secrethashes_to_lockedlocks[secrethash].amount
    assert lock_amount == amount + fee, msg

    secret_request_received.wait()

    app0_chain_state = views.state_from_app(app0)
    initiator_task = app0_chain_state.payment_mapping.secrethashes_to_task[secrethash]

    msg = "App0 should have never revealed the secret"
    transfer_state = initiator_task.manager_state.initiator_transfers[secrethash].transfer_state
    assert transfer_state != "transfer_secret_revealed", msg


@pytest.mark.parametrize("case_no", range(7))
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [4])
def test_mediated_transfer_with_fees(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait, case_no
):
    """
    Test mediation with a variety of fee schedules
    """
    raise_on_failure(
        raiden_network,
        run_test_mediated_transfer_with_fees,
        raiden_network=raiden_network,
        number_of_nodes=number_of_nodes,
        deposit=deposit,
        token_addresses=token_addresses,
        network_wait=network_wait,
        case_no=case_no,
    )


def run_test_mediated_transfer_with_fees(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait, case_no
):

    apps = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(apps[0])
    token_network_registry_address = apps[0].raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    def set_fee_schedule(app: App, other_app: App, fee_schedule: FeeScheduleState):
        channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state=views.state_from_raiden(app.raiden),
            token_network_address=token_network_address,
            partner_address=other_app.raiden.address,
        )
        assert channel_state
        action_update_fee = ActionChannelUpdateFee(
            canonical_identifier=channel_state.canonical_identifier, fee_schedule=fee_schedule
        )
        app.raiden.handle_state_changes(state_changes=[action_update_fee])

    def get_best_routes_with_fees(*args, **kwargs):
        routes = get_best_routes_internal(*args, **kwargs)
        for r in routes:
            r.estimated_fee = fee_without_margin
        return routes

    def assert_balances(expected_transferred_amounts=List[int]):
        for i, transferred_amount in enumerate(expected_transferred_amounts):
            assert_synced_channel_state(
                token_network_address=token_network_address,
                app0=apps[i],
                balance0=deposit - transferred_amount,
                pending_locks0=[],
                app1=apps[i + 1],
                balance1=deposit + transferred_amount,
                pending_locks1=[],
            )

    fee_without_margin = FeeAmount(20)
    fee = round(fee_without_margin * (1 + DEFAULT_MEDIATION_FEE_MARGIN))
    amount = PaymentAmount(10)
    cases = [
        # The fee is added by the initiator, but no mediator deducts fees. As a
        # result, the target receives the fee.
        dict(
            fee_schedules=[None, None, None],
            expected_transferred_amounts=[amount + fee, amount + fee, amount + fee],
        ),
        # The first mediator claims all of the fee.
        dict(
            fee_schedules=[None, FeeScheduleState(flat=fee), None],
            expected_transferred_amounts=[amount + fee, amount, amount],
        ),
        # The first mediator has a proportional fee of 20%
        dict(
            fee_schedules=[None, FeeScheduleState(proportional=0.20e6), None],
            expected_transferred_amounts=[
                amount + fee,
                amount + fee - (amount + fee) // 5,
                amount + fee - (amount + fee) // 5,
            ],
        ),
        # Both mediators have a proportional fee of 20%
        dict(
            fee_schedules=[
                None,
                FeeScheduleState(proportional=0.20e6),
                FeeScheduleState(proportional=0.20e6),
            ],
            expected_transferred_amounts=[
                amount + fee,
                amount + fee - (amount + fee) // 5,
                amount + fee - (amount + fee) // 5 - (amount + fee - (amount + fee) // 5) // 5,
            ],
        ),
        # The first mediator has an imbalance fee that works like a 20%
        # proportional fee when using the channel in this direction.
        dict(
            fee_schedules=[None, FeeScheduleState(imbalance_penalty=[(0, 0), (1000, 200)]), None],
            expected_transferred_amounts=[
                amount + fee,
                amount + fee - (amount + fee) // 5,
                amount + fee - (amount + fee) // 5,
            ],
        ),
        # Using the same fee_schedules as above on the incoming channel instead
        # of the outgoing channel of mediator 1 should yield the same result.
        dict(
            incoming_fee_schedules=[
                FeeScheduleState(imbalance_penalty=[(0, 0), (1000, 200)]),
                None,
                None,
            ],
            expected_transferred_amounts=[
                amount + fee,
                amount + fee - (amount + fee) // 5,
                amount + fee - (amount + fee) // 5,
            ],
        ),
        # The first mediator has an imbalance fee which will add one token for
        # for every token transferred as a reward for moving the channel into a
        # better state. This causes the target to receive more than the `amount
        # + fees` which is sent by the initiator.
        dict(
            fee_schedules=[None, FeeScheduleState(imbalance_penalty=[(0, 1000), (1000, 0)]), None],
            expected_transferred_amounts=[amount + fee, (amount + fee) * 2, (amount + fee) * 2],
        ),
    ]

    case = cases[case_no]
    for i, fee_schedule in enumerate(case.get("fee_schedules", [])):
        if fee_schedule:
            set_fee_schedule(apps[i], apps[i + 1], fee_schedule)
    for i, fee_schedule in enumerate(case.get("incoming_fee_schedules", [])):
        if fee_schedule:
            set_fee_schedule(apps[i + 1], apps[i], fee_schedule)

    route_patch = patch("raiden.routing.get_best_routes_internal", get_best_routes_with_fees)
    disable_max_mediation_fee_patch = patch(
        "raiden.transfer.mediated_transfer.initiator.MAX_MEDIATION_FEE_PERC", new=1
    )

    with route_patch, disable_max_mediation_fee_patch:
        transfer_and_assert_path(
            path=raiden_network, token_address=token_address, amount=amount, identifier=2
        )
    assert_balances(case["expected_transferred_amounts"])
