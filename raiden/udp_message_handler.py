# -*- coding: utf-8 -*-
import logging

from ethereum import slogging

from raiden.utils import random_secret
from raiden.routing import get_best_routes
from raiden.transfer import views
from raiden.transfer.state import balanceproof_from_envelope
from raiden.transfer.state_change import (
    ActionForTokenNetwork,
    ReceiveTransferDirect,
    ReceiveUnlock,
)
from raiden.transfer.mediated_transfer.state import lockedtransfer_from_message
from raiden.messages import (
    DirectTransfer,
    MediatedTransfer,
    Message,
    RefundTransfer,
    RevealSecret,
    Secret,
    SecretRequest,
)
from raiden.transfer.mediated_transfer.state_change import (
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
    ReceiveTransferRefundCancelRoute,
)

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


def handle_message_secretrequest(
        raiden: 'RaidenService',
        message: SecretRequest):
    secret_request = ReceiveSecretRequest(
        message.identifier,
        message.amount,
        message.hashlock,
        message.sender,
    )
    raiden.handle_state_change(secret_request)


def handle_message_revealsecret(
        raiden: 'RaidenService',
        message: RevealSecret):
    state_change = ReceiveSecretReveal(
        message.secret,
        message.sender,
    )
    raiden.handle_state_change(state_change)


def handle_message_secret(
        raiden: 'RaidenService',
        message: Secret):
    balance_proof = balanceproof_from_envelope(message)
    state_change = ReceiveUnlock(
        message.secret,
        balance_proof,
    )
    raiden.handle_state_change(state_change)


def handle_message_refundtransfer(
        raiden: 'RaidenService',
        message: RefundTransfer):
    registry_address = raiden.default_registry.address
    from_transfer = lockedtransfer_from_message(message)
    node_state = views.state_from_raiden(raiden)

    routes = get_best_routes(
        node_state,
        registry_address,
        from_transfer.token,
        raiden.address,
        from_transfer.target,
        from_transfer.lock.amount,
        message.sender,
    )

    role = views.get_transfer_role(
        node_state,
        from_transfer.lock.hashlock,
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
            routes,
            from_transfer,
        )

    raiden.handle_state_change(state_change)


def handle_message_directtransfer(
        raiden: 'RaidenService',
        message: DirectTransfer):
    payment_network_identifier = raiden.default_registry.address
    token_address = message.token
    balance_proof = balanceproof_from_envelope(message)

    direct_transfer = ReceiveTransferDirect(
        message.identifier,
        balance_proof,
    )

    state_change = ActionForTokenNetwork(
        payment_network_identifier,
        token_address,
        direct_transfer,
    )

    raiden.handle_state_change(state_change)


def handle_message_mediatedtransfer(
        raiden: 'RaidenService',
        message: MediatedTransfer):
    if message.target == raiden.address:
        raiden.target_mediated_transfer(message)
    else:
        raiden.mediate_mediated_transfer(message)


def on_udp_message(raiden: 'RaidenService', message: Message):
    if isinstance(message, SecretRequest):
        handle_message_secretrequest(raiden, message)
    elif isinstance(message, RevealSecret):
        handle_message_revealsecret(raiden, message)
    elif isinstance(message, Secret):
        handle_message_secret(raiden, message)
    elif isinstance(message, DirectTransfer):
        handle_message_directtransfer(raiden, message)
    elif isinstance(message, RefundTransfer):
        # The RefundTransfer must be prior to the MediatedTransfer, since a
        # RefundTransfer is also a MediatedTransfer
        handle_message_refundtransfer(raiden, message)
    elif isinstance(message, MediatedTransfer):
        handle_message_mediatedtransfer(raiden, message)
    elif log.isEnabledFor(logging.ERROR):
        # ack and ping messages are not forwarded to the handler
        log.error('Unknown message cmdid {}'.format(message.cmdid))
