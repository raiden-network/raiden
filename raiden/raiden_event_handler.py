# -*- coding: utf-8 -*-
import logging

from ethereum import slogging

from raiden.messages import (
    DirectTransfer,
    MediatedTransfer,
    RefundTransfer,
    RevealSecret,
    Secret,
    SecretRequest,
)
from raiden.transfer.events import (
    ContractSendChannelClose,
    ContractSendChannelSettle,
    ContractSendChannelUpdateTransfer,
    ContractSendChannelWithdraw,
    EventTransferReceivedSuccess,
    EventTransferSentFailed,
    EventTransferSentSuccess,
    SendDirectTransfer,
)
from raiden.transfer.mediated_transfer.events import (
    EventUnlockFailed,
    EventUnlockSuccess,
    EventWithdrawFailed,
    EventWithdrawSuccess,
    SendBalanceProof,
    SendMediatedTransfer,
    SendRefundTransfer,
    SendRevealSecret,
    SendSecretRequest,
)
from raiden.utils import pex

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name
UNEVENTFUL_EVENTS = (
    EventTransferReceivedSuccess,
    EventUnlockSuccess,
    EventWithdrawFailed,
    EventWithdrawSuccess,
)


def handle_send_mediatedtransfer(
        raiden: 'RaidenService',
        send_mediated_transfer: SendMediatedTransfer):
    mediated_transfer_message = MediatedTransfer.from_event(send_mediated_transfer)
    raiden.sign(mediated_transfer_message)
    raiden.send_async(
        mediated_transfer_message.recipient,
        mediated_transfer_message,
    )


def handle_send_directtransfer(
        raiden: 'RaidenService',
        send_direct_transfer: SendDirectTransfer):
    direct_transfer_message = DirectTransfer.from_event(send_direct_transfer)
    raiden.sign(direct_transfer_message)
    raiden.send_async(
        send_direct_transfer.recipient,
        direct_transfer_message,
    )


def handle_send_revealsecret(
        raiden: 'RaidenService',
        reveal_secret_event: SendRevealSecret):
    reveal_secret_message = RevealSecret.from_event(reveal_secret_event)
    raiden.sign(reveal_secret_message)
    raiden.send_async(
        reveal_secret_event.receiver,
        reveal_secret_message,
    )


def handle_send_balanceproof(
        raiden: 'RaidenService',
        balance_proof_event: SendBalanceProof):
    secret_message = Secret.from_event(balance_proof_event)
    raiden.sign(secret_message)
    raiden.send_async(
        balance_proof_event.receiver,
        secret_message,
    )


def handle_send_secretrequest(
        raiden: 'RaidenService',
        secret_request_event: SendSecretRequest):
    secret_request_message = SecretRequest.from_event(secret_request_event)
    raiden.sign(secret_request_message)
    raiden.send_async(
        secret_request_event.receiver,
        secret_request_message,
    )


def handle_send_refundtransfer(
        raiden: 'RaidenService',
        refund_transfer_event: SendRefundTransfer):
    refund_transfer_message = RefundTransfer.from_event(refund_transfer_event)
    raiden.sign(refund_transfer_message)
    raiden.send_async(
        refund_transfer_event.recipient,
        refund_transfer_message,
    )


def handle_transfersentsuccess(
        raiden: 'RaidenService',
        transfer_sent_success_event: EventTransferSentSuccess):
    for result in raiden.identifier_to_results[transfer_sent_success_event.identifier]:
        result.set(True)

    del raiden.identifier_to_results[transfer_sent_success_event.identifier]


def handle_transfersentfailed(
        raiden: 'RaidenService',
        transfer_sent_failed_event: EventTransferSentFailed):
    for result in raiden.identifier_to_results[transfer_sent_failed_event.identifier]:
        result.set(False)
    del raiden.identifier_to_results[transfer_sent_failed_event.identifier]


def handle_unlockfailed(
        raiden: 'RaidenService',
        unlock_failed_event: EventUnlockFailed):
    # pylint: disable=unused-argument
    log.error(
        'UnlockFailed!',
        hashlock=pex(unlock_failed_event.hashlock),
        reason=unlock_failed_event.reason
    )


def handle_contract_channelclose(
        raiden: 'RaidenService',
        channel_close_event: ContractSendChannelClose):
    balance_proof = channel_close_event.balance_proof

    if balance_proof:
        nonce = balance_proof.nonce
        transferred_amount = balance_proof.transferred_amount
        locksroot = balance_proof.locksroot
        signature = balance_proof.signature
        message_hash = balance_proof.message_hash

    else:
        nonce = 0
        transferred_amount = 0
        locksroot = ''
        signature = ''
        message_hash = ''

    channel = raiden.chain.netting_channel(channel_close_event.channel_identifier)

    channel.close(
        nonce,
        transferred_amount,
        locksroot,
        message_hash,
        signature,
    )


def handle_contract_channelupdate(
        raiden: 'RaidenService',
        channel_update_event: ContractSendChannelUpdateTransfer):
    balance_proof = channel_update_event.balance_proof

    if balance_proof:
        channel = raiden.chain.netting_channel(channel_update_event.channel_identifier)
        channel.update_transfer(
            balance_proof.nonce,
            balance_proof.transferred_amount,
            balance_proof.locksroot,
            balance_proof.message_hash,
            balance_proof.signature,
        )


def handle_contract_channelwithdraw(
        raiden: 'RaidenService',
        channel_withdraw_event: ContractSendChannelWithdraw):
    channel = raiden.chain.netting_channel(channel_withdraw_event.channel_identifier)
    channel.withdraw(channel_withdraw_event.unlock_proofs)


def handle_contract_channelsettle(
        raiden: 'RaidenService',
        channel_settle_event: ContractSendChannelSettle):
    channel = raiden.chain.netting_channel(channel_settle_event.channel_identifier)
    channel.settle()


def on_raiden_event(raiden: 'RaidenService', event: 'Event'):
    # pylint: disable=too-many-branches

    if isinstance(event, SendMediatedTransfer):
        handle_send_mediatedtransfer(raiden, event)
    elif isinstance(event, SendDirectTransfer):
        handle_send_directtransfer(raiden, event)
    elif isinstance(event, SendRevealSecret):
        handle_send_revealsecret(raiden, event)
    elif isinstance(event, SendBalanceProof):
        handle_send_balanceproof(raiden, event)
    elif isinstance(event, SendSecretRequest):
        handle_send_secretrequest(raiden, event)
    elif isinstance(event, SendRefundTransfer):
        handle_send_refundtransfer(raiden, event)
    elif isinstance(event, EventTransferSentSuccess):
        handle_transfersentsuccess(raiden, event)
    elif isinstance(event, EventTransferSentFailed):
        handle_transfersentfailed(raiden, event)
    elif isinstance(event, EventUnlockFailed):
        handle_unlockfailed(raiden, event)
    elif isinstance(event, ContractSendChannelClose):
        handle_contract_channelclose(raiden, event)
    elif isinstance(event, ContractSendChannelUpdateTransfer):
        handle_contract_channelupdate(raiden, event)
    elif isinstance(event, ContractSendChannelWithdraw):
        handle_contract_channelwithdraw(raiden, event)
    elif isinstance(event, ContractSendChannelSettle):
        handle_contract_channelsettle(raiden, event)
    elif isinstance(event, UNEVENTFUL_EVENTS):
        pass
    elif log.isEnabledFor(logging.ERROR):
        log.error('Unknown event {}'.format(type(event)))
