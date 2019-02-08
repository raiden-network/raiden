from collections import defaultdict
from unittest.mock import patch

import structlog
from gevent.event import AsyncResult

from raiden.message_handler import MessageHandler
from raiden.messages import Message
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.raiden_service import RaidenService
from raiden.tests.utils.events import check_nested_attrs
from raiden.transfer.architecture import Event as RaidenEvent, TransitionResult
from raiden.transfer.mediated_transfer.events import SendBalanceProof, SendSecretRequest
from raiden.utils import pex, typing

log = structlog.get_logger(__name__)


class MessageWaiting(typing.NamedTuple):
    attributes: dict
    message_type: type
    async_result: AsyncResult


class Hold(typing.NamedTuple):
    event: RaidenEvent
    event_type: type
    async_result: AsyncResult
    attributes: typing.Dict


class WaitForMessage(MessageHandler):
    def __init__(self):
        self.waiting = defaultdict(list)

    def wait_for_message(self, message_type: type, attributes: dict) -> AsyncResult:
        assert not any(attributes == waiting.attributes for waiting in self.waiting[message_type])
        waiting = MessageWaiting(
            attributes=attributes,
            message_type=Message,
            async_result=AsyncResult(),
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


class HoldRaidenEvent(RaidenEventHandler):
    """ Use this handler to stop the node from processing an event.

    This is useful:
    - Simulate network communication problems, by delaying when protocol
      messages are sent.
    - Simulate blockchain congestion, by delaying transactions.
    - Wait for a given state of the protocol, by waiting for an event to be
      available.
    """

    def __init__(self):
        self.eventtype_to_holds = defaultdict(list)

    def on_raiden_event(self, raiden: RaidenService, event: RaidenEvent):
        holds = self.eventtype_to_holds[type(event)]
        found = None

        for pos, hold in enumerate(holds):
            if check_nested_attrs(event, hold.attributes):
                msg = (
                    'Same event emitted twice, should not happen. '
                    'Either there is a bug in the state machine or '
                    'the hold.attributes is too generic and multiple '
                    'different events are matching.'
                )
                assert hold.event is None, msg

                newhold = hold._replace(event=event)
                found = (pos, newhold)
                break

        if found is not None:
            hold = found[1]
            holds[found[0]] = found[1]
            hold.async_result.set(event)
        else:
            super().on_raiden_event(raiden, event)

    def hold(self, event_type: type, attributes: typing.Dict) -> AsyncResult:
        hold = Hold(
            event=None,
            event_type=event_type,
            async_result=AsyncResult(),
            attributes=attributes,
        )
        self.eventtype_to_holds[event_type].append(hold)
        log.debug(f'Hold for {event_type.__name__} with {attributes} created.')
        return hold.async_result

    def release(self, raiden: RaidenService, event: RaidenEvent):
        holds = self.eventtype_to_holds[type(event)]
        found = None

        for pos, hold in enumerate(holds):
            if hold.event == event:
                found = (pos, hold)
                break

        msg = (
            'Cannot release unknown event. '
            'Either it was never held, the event was not emited yet, '
            'or it was released twice.'
        )
        assert found is not None, msg

        hold = holds.pop(found[0])
        super().on_raiden_event(raiden, event)
        log.debug(f'{event} released.', node=pex(raiden.address))

    def hold_secretrequest_for(self, secrethash: typing.SecretHash) -> AsyncResult:
        return self.hold(SendSecretRequest, {'secrethash': secrethash})

    def hold_unlock_for(self, secrethash: typing.SecretHash):
        return self.hold(SendBalanceProof, {'secrethash': secrethash})

    def release_secretrequest_for(self, raiden: RaidenService, secrethash: typing.SecretHash):
        for hold in self.eventtype_to_holds[SendSecretRequest]:
            if hold.attributes['secrethash'] == secrethash:
                self.release(raiden, hold.event)

    def release_unlock_for(self, raiden: RaidenService, secrethash: typing.SecretHash):
        for hold in self.eventtype_to_holds[SendBalanceProof]:
            if hold.attributes['secrethash'] == secrethash:
                self.release(raiden, hold.event)


def dont_handle_lock_expired_mock(app):
    """Takes in a raiden app and returns a mock context where lock_expired is not processed
    """
    def do_nothing(raiden, message):
        pass

    return patch.object(
        app.raiden.message_handler,
        'handle_message_lockexpired',
        side_effect=do_nothing,
    )


def dont_handle_node_change_network_state():
    """Returns a mock context where ActionChangeNodeNetworkState is not processed
    """
    def empty_state_transition(chain_state, state_change):
        return TransitionResult(chain_state, list())

    return patch(
        'raiden.transfer.node.handle_node_change_network_state',
        empty_state_transition,
    )


# backwards compatibility
HoldOffChainSecretRequest = HoldRaidenEvent
