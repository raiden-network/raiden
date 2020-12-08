from typing import cast
from unittest.mock import Mock, call, patch
from uuid import UUID, uuid4

from raiden.constants import LOCKSROOT_OF_NO_LOCKS, RoutingMode
from raiden.network.proxies.token_network import ParticipantDetails, ParticipantsDetails
from raiden.raiden_event_handler import PFSFeedbackEventHandler, RaidenEventHandler
from raiden.raiden_service import RaidenService
from raiden.tests.utils.factories import (
    make_address,
    make_block_hash,
    make_canonical_identifier,
    make_channel_identifier,
    make_locksroot,
    make_payment_id,
    make_secret,
    make_secret_hash,
    make_token_network_address,
    make_token_network_registry_address,
)
from raiden.tests.utils.mocks import make_raiden_service_mock
from raiden.transfer.events import ContractSendChannelBatchUnlock, EventPaymentSentSuccess
from raiden.transfer.mediated_transfer.events import EventRouteFailed
from raiden.transfer.state import ChainState
from raiden.transfer.utils import hash_balance_data
from raiden.transfer.views import get_channelstate_by_token_network_and_partner, state_from_raiden
from raiden.utils.typing import (
    Address,
    ChannelID,
    List,
    LockedAmount,
    Nonce,
    Optional,
    PaymentAmount,
    TargetAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    Tuple,
    WithdrawAmount,
)


def test_handle_contract_send_channelunlock_already_unlocked():
    """This is a test for the scenario where the onchain unlock has
    already happened when we get to handle our own send unlock
    transaction.

    Regression test for https://github.com/raiden-network/raiden/issues/3152
    """
    channel_identifier = ChannelID(1)
    token_network_registry_address = make_token_network_registry_address()
    token_network_address = make_token_network_address()
    participant = make_address()
    raiden = make_raiden_service_mock(
        token_network_registry_address=token_network_registry_address,
        token_network_address=token_network_address,
        channel_identifier=channel_identifier,
        partner=participant,
    )

    channel_state = get_channelstate_by_token_network_and_partner(
        chain_state=state_from_raiden(raiden),
        token_network_address=token_network_address,
        partner_address=participant,
    )
    assert channel_state

    channel_state.our_state.onchain_locksroot = LOCKSROOT_OF_NO_LOCKS
    channel_state.partner_state.onchain_locksroot = LOCKSROOT_OF_NO_LOCKS

    def detail_participants(_participant1, _participant2, _block_identifier, _channel_identifier):
        transferred_amount = TokenAmount(1)
        locked_amount = LockedAmount(1)
        locksroot = make_locksroot()
        balance_hash = hash_balance_data(transferred_amount, locked_amount, locksroot)
        our_details = ParticipantDetails(
            address=raiden.address,
            deposit=TokenAmount(5),
            withdrawn=WithdrawAmount(0),
            is_closer=False,
            balance_hash=balance_hash,
            nonce=Nonce(1),
            locksroot=locksroot,
            locked_amount=locked_amount,
        )

        transferred_amount = TokenAmount(1)
        locked_amount = LockedAmount(1)
        # Let's mock here that partner locksroot is 0x0
        balance_hash = hash_balance_data(transferred_amount, locked_amount, locksroot)
        partner_details = ParticipantDetails(
            address=participant,
            deposit=TokenAmount(5),
            withdrawn=WithdrawAmount(0),
            is_closer=True,
            balance_hash=balance_hash,
            nonce=Nonce(1),
            locksroot=LOCKSROOT_OF_NO_LOCKS,
            locked_amount=locked_amount,
        )
        return ParticipantsDetails(our_details, partner_details)

    # make sure detail_participants returns partner data with a locksroot of 0x0
    raiden.proxy_manager.token_network.detail_participants = detail_participants

    event = ContractSendChannelBatchUnlock(
        canonical_identifier=make_canonical_identifier(
            token_network_address=token_network_address, channel_identifier=channel_identifier
        ),
        sender=participant,
        triggered_by_block_hash=make_block_hash(),
    )

    # This should not throw an unrecoverable error
    RaidenEventHandler().on_raiden_events(
        raiden=raiden, chain_state=raiden.wal.get_current_state(), events=[event]
    )


def setup_pfs_handler_test(
    set_feedback_token: bool,
) -> Tuple[
    RaidenService,
    PFSFeedbackEventHandler,
    TokenNetworkRegistryAddress,
    TokenNetworkAddress,
    List[Address],
    Optional[UUID],
]:
    channel_identifier = make_channel_identifier()
    token_network_registry_address = make_token_network_registry_address()
    token_network_address = make_token_network_address()
    participant = make_address()
    raiden = make_raiden_service_mock(
        token_network_registry_address=token_network_registry_address,
        token_network_address=token_network_address,
        channel_identifier=channel_identifier,
        partner=participant,
    )

    default_handler = RaidenEventHandler()
    pfs_handler = PFSFeedbackEventHandler(default_handler)

    route = [make_address(), make_address(), make_address()]

    # Set PFS config and feedback token
    pfs_config = True  # just a truthy value
    raiden.config.pfs_config = pfs_config

    feedback_uuid = None
    if set_feedback_token:
        feedback_uuid = uuid4()
        raiden.route_to_feedback_token[tuple(route)] = feedback_uuid

    return (
        raiden,
        pfs_handler,
        token_network_registry_address,
        token_network_address,
        route,
        feedback_uuid,
    )


def test_pfs_handler_handle_routefailed_with_feedback_token():
    raiden, pfs_handler, _, token_network_address, route, feedback_uuid = setup_pfs_handler_test(
        set_feedback_token=True
    )

    route_failed_event = EventRouteFailed(
        secrethash=make_secret_hash(), route=route, token_network_address=token_network_address
    )

    with patch("raiden.raiden_event_handler.post_pfs_feedback") as pfs_feedback_handler:
        pfs_handler.on_raiden_events(
            raiden=raiden,
            chain_state=cast(ChainState, raiden.wal.get_current_state()),  # type: ignore
            events=[route_failed_event],
        )
    assert pfs_feedback_handler.called
    assert pfs_feedback_handler.call_args == call(
        pfs_config=raiden.config.pfs_config,
        route=route,
        routing_mode=RoutingMode.PRIVATE,
        successful=False,
        token=feedback_uuid,
        token_network_address=token_network_address,
    )


def test_pfs_handler_handle_routefailed_without_feedback_token():
    raiden, pfs_handler, _, token_network_address, route, _ = setup_pfs_handler_test(
        set_feedback_token=False
    )

    route_failed_event = EventRouteFailed(
        secrethash=make_secret_hash(), route=route, token_network_address=token_network_address
    )

    with patch("raiden.raiden_event_handler.post_pfs_feedback") as pfs_feedback_handler:
        pfs_handler.on_raiden_events(
            raiden=raiden,
            chain_state=cast(ChainState, raiden.wal.get_current_state()),  # type: ignore
            events=[route_failed_event],
        )
    assert not pfs_feedback_handler.called


def test_pfs_handler_handle_paymentsentsuccess_with_feedback_token():
    (
        raiden,
        pfs_handler,
        token_network_registry_address,
        token_network_address,
        route,
        feedback_uuid,
    ) = setup_pfs_handler_test(set_feedback_token=True)

    payment_id = make_payment_id()
    amount = PaymentAmount(123)
    target = TargetAddress(route[-1])
    raiden.targets_to_identifiers_to_statuses[target][payment_id] = Mock()

    route_failed_event = EventPaymentSentSuccess(
        token_network_registry_address=token_network_registry_address,
        token_network_address=token_network_address,
        identifier=payment_id,
        amount=amount,
        target=TargetAddress(target),
        secret=make_secret(),
        route=route,
    )

    with patch("raiden.raiden_event_handler.post_pfs_feedback") as pfs_feedback_handler:
        pfs_handler.on_raiden_events(
            raiden=raiden,
            chain_state=cast(ChainState, raiden.wal.get_current_state()),  # type: ignore
            events=[route_failed_event],
        )
    assert pfs_feedback_handler.called
    assert pfs_feedback_handler.call_args == call(
        pfs_config=raiden.config.pfs_config,
        route=route,
        routing_mode=RoutingMode.PRIVATE,
        successful=True,
        token=feedback_uuid,
        token_network_address=token_network_address,
    )


def test_pfs_handler_handle_paymentsentsuccess_without_feedback_token():
    (
        raiden,
        pfs_handler,
        token_network_registry_address,
        token_network_address,
        route,
        _,
    ) = setup_pfs_handler_test(set_feedback_token=False)

    payment_id = make_payment_id()
    amount = PaymentAmount(123)
    target = TargetAddress(route[-1])
    raiden.targets_to_identifiers_to_statuses[target][payment_id] = Mock()

    route_failed_event = EventPaymentSentSuccess(
        token_network_registry_address=token_network_registry_address,
        token_network_address=token_network_address,
        identifier=payment_id,
        amount=amount,
        target=TargetAddress(target),
        secret=make_secret(),
        route=route,
    )

    with patch("raiden.raiden_event_handler.post_pfs_feedback") as pfs_feedback_handler:
        pfs_handler.on_raiden_events(
            raiden=raiden,
            chain_state=cast(ChainState, raiden.wal.get_current_state()),  # type: ignore
            events=[route_failed_event],
        )
    assert not pfs_feedback_handler.called
