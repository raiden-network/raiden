from collections import defaultdict
from unittest.mock import patch

import structlog
from gevent.event import AsyncResult

from raiden.message_handler import MessageHandler
from raiden.messages.abstract import Message
from raiden.raiden_event_handler import EventHandler
from raiden.raiden_service import RaidenService
from raiden.tests.utils.events import check_nested_attrs
from raiden.transfer.architecture import Event as RaidenEvent, TransitionResult
from raiden.transfer.mediated_transfer.events import SendSecretRequest, SendUnlock
from raiden.transfer.state import ChainState
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import Callable, Dict, List, NamedTuple, SecretHash, Set

log = structlog.get_logger(__name__)


class MessageWaiting(NamedTuple):
    attributes: dict
    message_type: type
    async_result: AsyncResult


class HoldWait(NamedTuple):
    event_type: type
    async_result: AsyncResult
    attributes: Dict


class Holding(NamedTuple):
    event: RaidenEvent
    chain_state: ChainState
    event_type: type
    async_result: AsyncResult
    attributes: Dict


class WaitForMessage(MessageHandler):
    def __init__(self):
        self.waiting: Dict[type, list] = defaultdict(list)

    def wait_for_message(self, message_type: type, attributes: dict) -> AsyncResult:
        assert not any(attributes == waiting.attributes for waiting in self.waiting[message_type])
        waiting = MessageWaiting(
            attributes=attributes, message_type=Message, async_result=AsyncResult()
        )
        self.waiting[message_type].append(waiting)
        return waiting.async_result

    def on_messages(self, raiden: RaidenService, messages: List[Message]) -> None:
        # First handle the message, and then set the events, to ensure the
        # expected side-effects of the message are applied
        super().on_messages(raiden, messages)

        for message in messages:
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
        self.eventtype_to_waitingholds: Dict[type, List[HoldWait]] = defaultdict(list)
        self.eventtype_to_holdings: Dict[type, List[Holding]] = defaultdict(list)
        self.pre_hooks: Set[Callable] = set()

    def on_raiden_events(
        self, raiden: RaidenService, chain_state: ChainState, events: List[RaidenEvent]
    ):
        events_to_dispatch = list()

        for event in events:
            for hook in self.pre_hooks:
                hook(event)

            event_type = type(event)
            # First check that there are no overlapping holds, otherwise the test
            # is likely flaky. It should either reuse the hold for the same event
            # or different holds must match a unique event.
            for hold in self.eventtype_to_holdings[event_type]:
                if check_nested_attrs(event, hold.attributes):
                    msg = (
                        f"Matching event of type {event.__class__.__name__} emitted "
                        f"twice, this should not happen. Either there is a bug in the "
                        f"state machine or the hold.attributes is too generic and "
                        f"multiple different events are matching. Event: {event} "
                        f"Attributes: {hold.attributes}"
                    )
                    raise RuntimeError(msg)

            waitingholds = self.eventtype_to_waitingholds[event_type]
            for pos, waiting_hold in enumerate(waitingholds):

                # If it is a match:
                # - Delete the waiting hold and add it to the holding
                # - Do not dispatch the event
                # - Notify the test by setting the async_result
                if check_nested_attrs(event, waiting_hold.attributes):
                    holding = Holding(
                        event=event,
                        chain_state=chain_state,
                        event_type=waiting_hold.event_type,
                        async_result=waiting_hold.async_result,
                        attributes=waiting_hold.attributes,
                    )
                    del self.eventtype_to_waitingholds[event_type][pos]
                    self.eventtype_to_holdings[event_type].append(holding)
                    waiting_hold.async_result.set(event)
                    break
            else:
                # Only dispatch the event if it didn't match any of the holds
                events_to_dispatch.append(event)

        if events_to_dispatch:
            self.wrapped.on_raiden_events(raiden, chain_state, events_to_dispatch)

    def hold(self, event_type: type, attributes: Dict) -> AsyncResult:
        hold = HoldWait(event_type=event_type, async_result=AsyncResult(), attributes=attributes)
        self.eventtype_to_waitingholds[event_type].append(hold)
        log.debug(f"Hold for {event_type.__name__} with {attributes} created.")
        return hold.async_result

    def release(self, raiden: RaidenService, event: RaidenEvent):
        holds = self.eventtype_to_holdings[type(event)]
        found = None

        for pos, hold in enumerate(holds):
            if hold.event == event:
                found = (pos, hold)
                break

        msg = (
            "Cannot release unknown event. "
            "Either it was never held, or the event was not emitted yet, "
            "or it was released twice."
        )
        assert found is not None, msg

        hold = holds.pop(found[0])
        self.wrapped.on_raiden_events(raiden, hold.chain_state, [event])
        log.debug(f"{event} released.", node=to_checksum_address(raiden.address))

    def hold_secretrequest_for(self, secrethash: SecretHash) -> AsyncResult:
        return self.hold(SendSecretRequest, {"secrethash": secrethash})

    def hold_unlock_for(self, secrethash: SecretHash):
        return self.hold(SendUnlock, {"secrethash": secrethash})

    def release_secretrequest_for(self, raiden: RaidenService, secrethash: SecretHash):
        for hold in self.eventtype_to_holdings[SendSecretRequest]:
            if hold.attributes["secrethash"] == secrethash:
                self.release(raiden, hold.event)

    def release_unlock_for(self, raiden: RaidenService, secrethash: SecretHash):
        for hold in self.eventtype_to_holdings[SendUnlock]:
            if hold.attributes["secrethash"] == secrethash:
                self.release(raiden, hold.event)


def dont_handle_lock_expired_mock(app):
    """Takes in a raiden app and returns a mock context where lock_expired is not processed
    """

    def do_nothing(raiden, message):  # pylint: disable=unused-argument
        return []

    return patch.object(
        app.raiden.message_handler, "handle_message_lockexpired", side_effect=do_nothing
    )


def dont_handle_node_change_network_state():
    """Returns a mock context where ActionChangeNodeNetworkState is not processed
    """

    def empty_state_transition(chain_state, state_change):  # pylint: disable=unused-argument
        return TransitionResult(chain_state, list())

    return patch(
        "raiden.transfer.node.handle_action_change_node_network_state", empty_state_transition
    )
