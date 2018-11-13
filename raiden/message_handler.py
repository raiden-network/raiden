import structlog

from raiden.messages import (
    Delivered,
    DirectTransfer,
    LockedTransfer,
    LockExpired,
    Message,
    Processed,
    RefundTransfer,
    RevealSecret,
    Secret,
    SecretRequest,
)
from raiden.raiden_service import RaidenService
from raiden.routing import get_best_routes
from raiden.transfer import views
from raiden.transfer.mediated_transfer.state import lockedtransfersigned_from_message
from raiden.transfer.mediated_transfer.state_change import (
    ReceiveLockExpired,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
    ReceiveTransferRefundCancelRoute,
)
from raiden.transfer.state import balanceproof_from_envelope
from raiden.transfer.state_change import (
    ReceiveDelivered,
    ReceiveProcessed,
    ReceiveTransferDirect,
    ReceiveUnlock,
)
from raiden.utils import pex, random_secret

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class MessageHandler:
    # pylint: disable=no-self-use

    def on_message(self, raiden: RaidenService, message: Message):
        # pylint: disable=unidiomatic-typecheck

        if type(message) == SecretRequest:
            self.handle_message_secretrequest(raiden, message)
        elif type(message) == RevealSecret:
            self.handle_message_revealsecret(raiden, message)
        elif type(message) == Secret:
            self.handle_message_secret(raiden, message)
        elif type(message) == LockExpired:
            self.handle_message_lockexpired(raiden, message)
        elif type(message) == DirectTransfer:
            self.handle_message_directtransfer(raiden, message)
        elif type(message) == RefundTransfer:
            self.handle_message_refundtransfer(raiden, message)
        elif type(message) == LockedTransfer:
            self.handle_message_lockedtransfer(raiden, message)
        elif type(message) == Delivered:
            self.handle_message_delivered(raiden, message)
        elif type(message) == Processed:
            self.handle_message_processed(raiden, message)
        else:
            log.error('Unknown message cmdid {}'.format(message.cmdid))

    def handle_message_secretrequest(self, raiden: RaidenService, message: SecretRequest):
        secret_request = ReceiveSecretRequest(
            message.payment_identifier,
            message.amount,
            message.expiration,
            message.secrethash,
            message.sender,
        )
        raiden.handle_state_change(secret_request)

    def handle_message_revealsecret(self, raiden: RaidenService, message: RevealSecret):
        state_change = ReceiveSecretReveal(
            message.secret,
            message.sender,
        )
        raiden.handle_state_change(state_change)

    def handle_message_secret(self, raiden: RaidenService, message: Secret):
        balance_proof = balanceproof_from_envelope(message)
        state_change = ReceiveUnlock(
            message_identifier=message.message_identifier,
            secret=message.secret,
            balance_proof=balance_proof,
        )
        raiden.handle_state_change(state_change)

    def handle_message_lockexpired(self, raiden: RaidenService, message: LockExpired):
        balance_proof = balanceproof_from_envelope(message)
        state_change = ReceiveLockExpired(
            balance_proof=balance_proof,
            secrethash=message.secrethash,
            message_identifier=message.message_identifier,
        )
        raiden.handle_state_change(state_change)

    def handle_message_refundtransfer(self, raiden: RaidenService, message: RefundTransfer):
        token_network_address = message.token_network_address
        from_transfer = lockedtransfersigned_from_message(message)
        chain_state = views.state_from_raiden(raiden)

        routes = get_best_routes(
            chain_state,
            token_network_address,
            raiden.address,
            from_transfer.target,
            from_transfer.lock.amount,
            message.sender,
        )

        role = views.get_transfer_role(
            chain_state,
            from_transfer.lock.secrethash,
        )

        if role == 'initiator':
            secret = random_secret()
            state_change = ReceiveTransferRefundCancelRoute(
                routes=routes,
                transfer=from_transfer,
                secret=secret,
            )
        else:
            state_change = ReceiveTransferRefund(
                transfer=from_transfer,
                routes=routes,
            )

        raiden.handle_state_change(state_change)

    def handle_message_directtransfer(self, raiden: RaidenService, message: DirectTransfer):
        token_network_identifier = message.token_network_address
        balance_proof = balanceproof_from_envelope(message)

        direct_transfer = ReceiveTransferDirect(
            token_network_identifier,
            message.message_identifier,
            message.payment_identifier,
            balance_proof,
        )

        raiden.handle_state_change(direct_transfer)

    def handle_message_lockedtransfer(self, raiden: RaidenService, message: LockedTransfer):
        secret_hash = message.lock.secrethash
        if raiden.default_secret_registry.check_registered(secret_hash):
            log.warning(
                f'Ignoring received locked transfer with secrethash {pex(secret_hash)} '
                f'since it is already registered in the secret registry',
            )
            return

        if message.target == raiden.address:
            raiden.target_mediated_transfer(message)
        else:
            raiden.mediate_mediated_transfer(message)

    def handle_message_processed(self, raiden: RaidenService, message: Processed):
        processed = ReceiveProcessed(message.sender, message.message_identifier)
        raiden.handle_state_change(processed)

    def handle_message_delivered(self, raiden: RaidenService, message: Delivered):
        delivered = ReceiveDelivered(message.sender, message.delivered_message_identifier)
        raiden.handle_state_change(delivered)
