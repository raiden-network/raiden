from collections import defaultdict

import gevent
import structlog
from eth_utils import to_checksum_address
from gevent.event import AsyncResult

from raiden.app import App
from raiden.message_handler import MessageHandler
from raiden.messages.abstract import Message
from raiden.raiden_event_handler import EventHandler
from raiden.raiden_service import RaidenService
from raiden.settings import DEFAULT_RETRY_TIMEOUT
from raiden.tests.utils.events import (
    check_nested_attrs,
    raiden_events_search_for_item,
    raiden_state_changes_search_for_item,
)
from raiden.tests.utils.typing import AppChannels
from raiden.transfer.architecture import Event as RaidenEvent, StateChange
from raiden.transfer.mediated_transfer.events import SendBalanceProof, SendSecretRequest
from raiden.transfer.state import ChainState
from raiden.utils.typing import (
    Address,
    Callable,
    Dict,
    List,
    Mapping,
    NamedTuple,
    Optional,
    PaymentNetworkAddress,
    SecretHash,
    TokenAddress,
    TokenAmount,
    Type,
)
from raiden.waiting import (
    wait_for_healthy,
    wait_for_newchannel,
    wait_for_participant_totaldeposit,
    wait_for_token_network,
)

log = structlog.get_logger(__name__)


def wait_for_alarm_start(
    raiden_apps: List[App], retry_timeout: float = DEFAULT_RETRY_TIMEOUT
) -> None:
    """Wait until all Alarm tasks start & set up the last_block"""
    apps = list(raiden_apps)

    while apps:
        app = apps[-1]

        if app.raiden.alarm.known_block_number is None:
            gevent.sleep(retry_timeout)
        else:
            apps.pop()


def wait_for_usable_channel(
    raiden: RaidenService,
    partner_address: Address,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
    our_deposit: TokenAmount,
    partner_deposit: TokenAmount,
    retry_timeout: float = DEFAULT_RETRY_TIMEOUT,
) -> None:
    """ Wait until the channel from app0 to app1 is usable.

    The channel and the deposits are registered, and the partner network state
    is reachable.
    """
    wait_for_newchannel(
        raiden=raiden,
        payment_network_address=payment_network_address,
        token_address=token_address,
        partner_address=partner_address,
        retry_timeout=retry_timeout,
    )

    # wait for our deposit
    wait_for_participant_totaldeposit(
        raiden=raiden,
        payment_network_address=payment_network_address,
        token_address=token_address,
        partner_address=partner_address,
        target_address=raiden.address,
        target_balance=our_deposit,
        retry_timeout=retry_timeout,
    )

    # wait for the partner deposit
    wait_for_participant_totaldeposit(
        raiden=raiden,
        payment_network_address=payment_network_address,
        token_address=token_address,
        partner_address=partner_address,
        target_address=partner_address,
        target_balance=partner_deposit,
        retry_timeout=retry_timeout,
    )

    wait_for_healthy(raiden=raiden, node_address=partner_address, retry_timeout=retry_timeout)


def wait_for_token_networks(
    raiden_apps: List[App],
    token_network_registry_address: PaymentNetworkAddress,
    token_addresses: List[TokenAddress],
    retry_timeout: float = DEFAULT_RETRY_TIMEOUT,
) -> None:
    for token_address in token_addresses:
        for app in raiden_apps:
            wait_for_token_network(
                app.raiden, token_network_registry_address, token_address, retry_timeout
            )


def wait_for_channels(
    app_channels: AppChannels,
    payment_network_address: PaymentNetworkAddress,
    token_addresses: List[TokenAddress],
    deposit: TokenAmount,
    retry_timeout: float = DEFAULT_RETRY_TIMEOUT,
) -> None:
    """ Wait until all channels are usable from both directions. """
    for app0, app1 in app_channels:
        for token_address in token_addresses:
            # app0 waits for the channel to be usable
            wait_for_usable_channel(
                raiden=app0.raiden,
                partner_address=app1.raiden.address,
                payment_network_address=payment_network_address,
                token_address=token_address,
                our_deposit=deposit,
                partner_deposit=deposit,
                retry_timeout=retry_timeout,
            )
            # app1 waits for the channel to be usable
            wait_for_usable_channel(
                raiden=app1.raiden,
                partner_address=app0.raiden.address,
                payment_network_address=payment_network_address,
                token_address=token_address,
                our_deposit=deposit,
                partner_deposit=deposit,
                retry_timeout=retry_timeout,
            )


def wait_for_raiden_event(
    raiden: RaidenService, item_type: Type[RaidenEvent], attributes: Mapping, retry_timeout: float
) -> Optional[RaidenEvent]:
    """Wait until an event is seen in the WAL events

    Note:
        This does not time out, use gevent.Timeout.
    """
    found = None
    while found is None:
        found = raiden_events_search_for_item(raiden, item_type, attributes)
        gevent.sleep(retry_timeout)
    return found


def wait_for_state_change(
    raiden: RaidenService, item_type: Type[StateChange], attributes: Mapping, retry_timeout: float
) -> Optional[StateChange]:
    """Wait until a state change is seen in the WAL

    Note:
        This does not time out, use gevent.Timeout.
    """
    found = None
    while found is None:
        found = raiden_state_changes_search_for_item(raiden, item_type, attributes)
        gevent.sleep(retry_timeout)

    return found


def wait_assert(func: Callable, *args, **kwargs) -> None:
    """ Utility to re-run `func` if it raises an assert. Return once `func`
    doesn't hit a failed assert anymore.

    This will loop forever unless a gevent.Timeout is used.
    """
    while True:
        try:
            func(*args, **kwargs)
        except AssertionError as e:
            try:
                gevent.sleep(0.5)
            except gevent.Timeout:
                raise e
        else:
            break


class MessageWaiting(NamedTuple):
    attributes: dict
    message_type: type
    async_result: AsyncResult


class Hold(NamedTuple):
    event: RaidenEvent
    chain_state: ChainState
    event_type: type
    async_result: AsyncResult
    attributes: Dict


class WaitForMessage(MessageHandler):
    def __init__(self):
        self.waiting = defaultdict(list)

    def wait_for_message(self, message_type: type, attributes: dict) -> AsyncResult:
        assert not any(attributes == waiting.attributes for waiting in self.waiting[message_type])
        waiting = MessageWaiting(
            attributes=attributes, message_type=Message, async_result=AsyncResult()
        )
        self.waiting[message_type].append(waiting)
        return waiting.async_result

    def on_message(self, raiden: RaidenService, message: Message) -> None:
        # First handle the message, and then set the events, to ensure the
        # expected side-effects of the message are applied
        super().on_message(raiden, message)

        for waiting in self.waiting[type(message)]:
            if check_nested_attrs(message, waiting.attributes):
                waiting.async_result.set(message)


class HoldRaidenEventHandler(EventHandler):
    """ Use this handler to stop the node from processing an event.

    This is useful:
    - Simulate network communication problems, by delaying when protocol
      messages are sent.
    - Simulate blockchain congestion, by delaying transactions.
    - Wait for a given state of the protocol, by waiting for an event to be
      available.
    """

    def __init__(self, wrapped_handler: EventHandler):
        self.wrapped = wrapped_handler
        self.eventtype_to_holds = defaultdict(list)

    def on_raiden_event(self, raiden: RaidenService, chain_state: ChainState, event: RaidenEvent):
        holds = self.eventtype_to_holds[type(event)]
        found = None

        for pos, hold in enumerate(holds):
            if check_nested_attrs(event, hold.attributes):
                msg = (
                    f"Matching event of type {event.__class__.__name__} emitted "
                    f"twice, this should not happen. Either there is a bug in the "
                    f"state machine or the hold.attributes is too generic and "
                    f"multiple different events are matching. Event: {event} "
                    f"Attributes: {hold.attributes}"
                )
                assert hold.event is None, msg

                newhold = hold._replace(event=event, chain_state=chain_state)
                found = (pos, newhold)
                break

        if found is not None:
            hold = found[1]
            holds[found[0]] = found[1]
            hold.async_result.set(event)
        else:
            self.wrapped.on_raiden_event(raiden, chain_state, event)

    def hold(self, event_type: type, attributes: Dict) -> AsyncResult:
        hold = Hold(
            event=None,
            chain_state=None,
            event_type=event_type,
            async_result=AsyncResult(),
            attributes=attributes,
        )
        self.eventtype_to_holds[event_type].append(hold)
        log.debug(f"Hold for {event_type.__name__} with {attributes} created.")
        return hold.async_result

    def release(self, raiden: RaidenService, event: RaidenEvent):
        holds = self.eventtype_to_holds[type(event)]
        found = None

        for pos, hold in enumerate(holds):
            if hold.event == event:
                found = (pos, hold)
                break

        msg = (
            "Cannot release unknown event. "
            "Either it was never held, the event was not emited yet, "
            "or it was released twice."
        )
        assert found is not None, msg

        hold = holds.pop(found[0])
        self.wrapped.on_raiden_event(raiden, hold.chain_state, event)
        log.debug(f"{event} released.", node=to_checksum_address(raiden.address))

    def hold_secretrequest_for(self, secrethash: SecretHash) -> AsyncResult:
        return self.hold(SendSecretRequest, {"secrethash": secrethash})

    def hold_unlock_for(self, secrethash: SecretHash):
        return self.hold(SendBalanceProof, {"secrethash": secrethash})

    def release_secretrequest_for(self, raiden: RaidenService, secrethash: SecretHash):
        for hold in self.eventtype_to_holds[SendSecretRequest]:
            if hold.attributes["secrethash"] == secrethash:
                self.release(raiden, hold.event)

    def release_unlock_for(self, raiden: RaidenService, secrethash: SecretHash):
        for hold in self.eventtype_to_holds[SendBalanceProof]:
            if hold.attributes["secrethash"] == secrethash:
                self.release(raiden, hold.event)
