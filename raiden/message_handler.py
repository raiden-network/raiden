import structlog

from raiden.messages import (
    Delivered,
    LockedTransfer,
    LockExpired,
    Message,
    Processed,
    RefundTransfer,
    RevealSecret,
    SecretRequest,
    Unlock,
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
from raiden.transfer.state_change import ReceiveDelivered, ReceiveProcessed, ReceiveUnlock
from raiden.utils import pex, random_secret, typing

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class MessageHandler:

    def on_message(self, raiden: RaidenService, message: Message):
        # pylint: disable=unidiomatic-typecheck

        if type(message) == SecretRequest:
            self.handle_message_secretrequest(raiden, message)
        elif type(message) == RevealSecret:
            self.handle_message_revealsecret(raiden, message)
        elif type(message) == Unlock:
            self.handle_message_unlock(raiden, message)
        elif type(message) == LockExpired:
            self.handle_message_lockexpired(raiden, message)
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

    @staticmethod
    def handle_message_secretrequest(raiden: RaidenService, message: SecretRequest):
        secret_request = ReceiveSecretRequest(
            message.payment_identifier,
            message.amount,
            message.expiration,
            message.secrethash,
            message.sender,
        )
        raiden.handle_state_change(secret_request)

    @staticmethod
    def handle_message_revealsecret(raiden: RaidenService, message: RevealSecret):
        state_change = ReceiveSecretReveal(
            message.secret,
            message.sender,
        )
        raiden.handle_state_change(state_change)

    @staticmethod
    def handle_message_unlock(raiden: RaidenService, message: Unlock):
        balance_proof = balanceproof_from_envelope(message)
        state_change = ReceiveUnlock(
            message_identifier=message.message_identifier,
            secret=message.secret,
            balance_proof=balance_proof,
        )
        raiden.handle_state_change(state_change)

    @staticmethod
    def handle_message_lockexpired(raiden: RaidenService, message: LockExpired):
        balance_proof = balanceproof_from_envelope(message)
        state_change = ReceiveLockExpired(
            balance_proof=balance_proof,
            secrethash=message.secrethash,
            message_identifier=message.message_identifier,
        )
        raiden.handle_state_change(state_change)

    @staticmethod
    def handle_message_refundtransfer(raiden: RaidenService, message: RefundTransfer):
        token_network_address = message.token_network_address
        from_transfer = lockedtransfersigned_from_message(message)
        chain_state = views.state_from_raiden(raiden)

        routes = get_best_routes(
            chain_state=chain_state,
            token_network_id=typing.TokenNetworkID(token_network_address),
            from_address=typing.InitiatorAddress(raiden.address),
            to_address=from_transfer.target,
            amount=from_transfer.lock.amount,
            previous_address=message.sender,
            config=raiden.config,
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

    @staticmethod
    def handle_message_lockedtransfer(raiden: RaidenService, message: LockedTransfer):
        secret_hash = message.lock.secrethash
        # LEFTODO: Supply a proper block id
        registered = raiden.default_secret_registry.check_registered(
            secrethash=secret_hash,
            block_identifier='latest',
        )
        if registered:
            log.warning(
                f'Ignoring received locked transfer with secrethash {pex(secret_hash)} '
                f'since it is already registered in the secret registry',
            )
            return

        if message.target == raiden.address:
            raiden.target_mediated_transfer(message)
        else:
            raiden.mediate_mediated_transfer(message)

    @staticmethod
    def handle_message_processed(raiden: RaidenService, message: Processed):
        processed = ReceiveProcessed(message.sender, message.message_identifier)
        raiden.handle_state_change(processed)

    @staticmethod
    def handle_message_delivered(raiden: RaidenService, message: Delivered):
        delivered = ReceiveDelivered(message.sender, message.delivered_message_identifier)
        raiden.handle_state_change(delivered)
