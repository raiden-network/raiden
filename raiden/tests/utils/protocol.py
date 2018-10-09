import logging

from raiden.raiden_event_handler import RaidenEventHandler
from raiden.raiden_service import RaidenService
from raiden.transfer.mediated_transfer.events import SendSecretRequest
from raiden.utils import pex

log = logging.getLogger(__name__)


class HoldOffChainSecretRequest(RaidenEventHandler):
    """ Use this handler to stop the target from requesting the secret.

    This is used to simulate network communication problems. The message
    SecretRequest is used because the participants state can be expected to be
    consistent.
    """

    def __init__(self):
        self.secrethashes_to_hold = list()

    def hold_secret_for(self, secrethash):
        if secrethash not in self.secrethashes_to_hold:
            self.secrethashes_to_hold.append(secrethash)

    def handle_send_secretrequest(
            self,
            raiden: RaidenService,
            secret_request_event: SendSecretRequest,
    ):
        if secret_request_event.secrethash not in self.secrethashes_to_hold:
            super().handle_send_secretrequest(raiden, secret_request_event)
        else:
            log.info(f'SecretRequest for {pex(secret_request_event.secrethash)} held.')
