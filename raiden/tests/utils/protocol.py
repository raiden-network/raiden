from collections import defaultdict

import structlog
from gevent.event import Event

from raiden.message_handler import MessageHandler
from raiden.messages import Message
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.raiden_service import RaidenService
from raiden.tests.utils.events import check_nested_attrs
from raiden.transfer.mediated_transfer.events import SendSecretRequest
from raiden.utils import pex, typing

log = structlog.get_logger(__name__)


class MessageWaiting(typing.NamedTuple):
    attributes: dict
    message_received_event: Event


class SecretRequestState(typing.NamedTuple):
    secrethash: bytes
    secret_request_available: Event
    secret_request_event: SendSecretRequest


class WaitForMessage(MessageHandler):
    def __init__(self):
        self.waiting = defaultdict(list)

    def wait_for_message(self, message_type: Message, attributes: dict):
        assert not any(attributes == waiting.attributes for waiting in self.waiting[message_type])
        event = Event()
        self.waiting[message_type].append(MessageWaiting(attributes, event))
        return event

    def on_message(self, raiden: RaidenService, message: Message):
        # First handle the message, and then set the events, to ensure the
        # expected side-effects of the message is applied
        super().on_message(raiden, message)

        for waiting in self.waiting[type(message)]:
            if check_nested_attrs(message, waiting.attributes):
                waiting.message_received_event.set()


class HoldOffChainSecretRequest(RaidenEventHandler):
    """ Use this handler to stop the target from requesting the secret.

    This is used to simulate network communication problems. The message
    SecretRequest is used because the participants state can be expected to be
    consistent.
    """

    def __init__(self):
        self.secrethashes_to_hold = dict()

    def hold_secretrequest_for(self, secrethash: typing.SecretHash):
        assert secrethash not in self.secrethashes_to_hold

        waiting_event = Event()
        self.secrethashes_to_hold[secrethash] = SecretRequestState(
            secrethash=secrethash,
            secret_request_available=waiting_event,
            secret_request_event=None,
        )

        return waiting_event

    def release_secretrequest_for(self, raiden: RaidenService, secrethash: typing.SecretHash):
        hold_state = self.secrethashes_to_hold.get(secrethash)

        if hold_state and hold_state.secret_request_available.is_set():
            secret_request_event = hold_state.secret_request_event
            assert secret_request_event
            del self.secrethashes_to_hold[secrethash]

            super().handle_send_secretrequest(raiden, secret_request_event)
            log.info(
                f'SecretRequest for {pex(secret_request_event.secrethash)} released.',
                node=pex(raiden.address),
            )

    def handle_send_secretrequest(
            self,
            raiden: RaidenService,
            secret_request_event: SendSecretRequest,
    ):
        hold_state = self.secrethashes_to_hold.get(secret_request_event.secrethash)
        if hold_state is None:
            super().handle_send_secretrequest(raiden, secret_request_event)
        else:
            new_hold_state = hold_state._replace(secret_request_event=secret_request_event)
            new_hold_state.secret_request_available.set()
            self.secrethashes_to_hold[secret_request_event.secrethash] = new_hold_state
            log.info(
                f'SecretRequest for {pex(secret_request_event.secrethash)} held.',
                node=pex(raiden.address),
            )
