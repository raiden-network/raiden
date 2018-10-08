import structlog
from gevent.event import Event

from raiden.raiden_event_handler import RaidenEventHandler
from raiden.raiden_service import RaidenService
from raiden.transfer.mediated_transfer.events import SendSecretRequest
from raiden.utils import pex, typing

log = structlog.get_logger(__name__)


class SecretRequestState(typing.NamedTuple):
    secrethash: bytes
    secret_request_available: Event
    secret_request_event: SendSecretRequest


class HoldOffChainSecretRequest(RaidenEventHandler):
    """ Use this handler to stop the target from requesting the secret.

    This is used to simulate network communication problems. The message
    SecretRequest is used because the participants state can be expected to be
    consistent.
    """

    def __init__(self):
        self.secrethashes_to_hold = dict()

    def hold_secretrequest_for(self, secrethash: typing.SecretHash):
        if secrethash not in self.secrethashes_to_hold:
            waiting_event = Event()
            self.secrethashes_to_hold[secrethash] = SecretRequestState(
                secrethash=secrethash,
                secret_request_available=waiting_event,
                secret_request_event=None,
            )
        else:
            waiting_event = self.secrethashes_to_hold[secrethash].secret_request_available

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
