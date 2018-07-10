import structlog

from raiden.raiden_service import RaidenService
from raiden.utils import random_secret
from raiden.routing import get_best_routes
from raiden.transfer import views
from raiden.transfer.state import balanceproof_from_envelope
from raiden.transfer.state_change import (
    ReceiveProcessed,
    ReceiveTransferDirect,
    ReceiveUnlock,
)
from raiden.messages import (
    DirectTransfer,
    LockedTransfer,
    Message,
    Processed,
    RefundTransfer,
    RevealSecret,
    Secret,
    SecretRequest,
)
from raiden.transfer.mediated_transfer.state import lockedtransfersigned_from_message
from raiden.transfer.mediated_transfer.state_change import (
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
    ReceiveTransferRefundCancelRoute,
)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def handle_message_secretrequest(raiden: RaidenService, message: SecretRequest):
    secret_request = ReceiveSecretRequest(
        message.payment_identifier,
        message.amount,
        message.secrethash,
        message.sender,
    )
    raiden.handle_state_change(secret_request)


def handle_message_revealsecret(raiden: RaidenService, message: RevealSecret):
    state_change = ReceiveSecretReveal(
        message.secret,
        message.sender,
    )
    raiden.handle_state_change(state_change)


def handle_message_secret(raiden: RaidenService, message: Secret):
    balance_proof = balanceproof_from_envelope(message)
    state_change = ReceiveUnlock(
        message_identifier=message.message_identifier,
        secret=message.secret,
        balance_proof=balance_proof,
    )
    raiden.handle_state_change(state_change)


def handle_message_refundtransfer(raiden: RaidenService, message: RefundTransfer):
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
            message.sender,
            routes,
            from_transfer,
            secret,
        )
    else:
        state_change = ReceiveTransferRefund(
            message.sender,
            from_transfer,
            routes,
        )

    raiden.handle_state_change(state_change)


def handle_message_directtransfer(raiden: RaidenService, message: DirectTransfer):
    token_network_identifier = message.token_network_address
    balance_proof = balanceproof_from_envelope(message)

    direct_transfer = ReceiveTransferDirect(
        token_network_identifier,
        message.message_identifier,
        message.payment_identifier,
        balance_proof,
    )

    raiden.handle_state_change(direct_transfer)


def handle_message_lockedtransfer(raiden: RaidenService, message: LockedTransfer):
    if message.target == raiden.address:
        raiden.target_mediated_transfer(message)
    else:
        raiden.mediate_mediated_transfer(message)


def handle_message_processed(raiden: RaidenService, message: Processed):
    processed = ReceiveProcessed(message.message_identifier)
    raiden.handle_state_change(processed)


def on_message(raiden: RaidenService, message: Message):
    """ Return True if the message is known. """
    # pylint: disable=unidiomatic-typecheck
    if type(message) == SecretRequest:
        handle_message_secretrequest(raiden, message)
    elif type(message) == RevealSecret:
        handle_message_revealsecret(raiden, message)
    elif type(message) == Secret:
        handle_message_secret(raiden, message)
    elif type(message) == DirectTransfer:
        handle_message_directtransfer(raiden, message)
    elif type(message) == RefundTransfer:
        handle_message_refundtransfer(raiden, message)
    elif type(message) == LockedTransfer:
        handle_message_lockedtransfer(raiden, message)
    elif type(message) == Processed:
        handle_message_processed(raiden, message)
    else:
        log.error('Unknown message cmdid {}'.format(message.cmdid))
        return False

    # Inform the transport that it's okay to send a Delivered message
    return True
