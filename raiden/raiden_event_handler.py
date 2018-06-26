import structlog

from raiden.messages import (
    message_from_sendevent,
    Lock,
)
from raiden.transfer.architecture import Event
from raiden.transfer.events import (
    ContractSendSecretReveal,
    ContractSendChannelClose,
    ContractSendChannelSettle,
    ContractSendChannelUpdateTransfer,
    ContractSendChannelBatchUnlock,
    EventTransferReceivedSuccess,
    EventTransferSentFailed,
    EventTransferSentSuccess,
    SendDirectTransfer,
    SendProcessed,
)
from raiden.transfer.mediated_transfer.events import (
    EventUnlockFailed,
    EventUnlockSuccess,
    EventUnlockClaimFailed,
    EventUnlockClaimSuccess,
    SendBalanceProof,
    SendLockedTransfer,
    SendRefundTransfer,
    SendRevealSecret,
    SendSecretRequest,
)
from raiden.transfer.balance_proof import signing_update_data
from raiden.utils import pex
# type alias to avoid both circular dependencies and flake8 errors
RaidenService = 'RaidenService'

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name
UNEVENTFUL_EVENTS = (
    EventTransferReceivedSuccess,
    EventUnlockSuccess,
    EventUnlockClaimFailed,
    EventUnlockClaimSuccess,
)


def handle_send_lockedtransfer(
        raiden: RaidenService,
        send_locked_transfer: SendLockedTransfer,
):
    mediated_transfer_message = message_from_sendevent(send_locked_transfer, raiden.address)
    raiden.sign(mediated_transfer_message)
    raiden.transport.send_async(
        mediated_transfer_message.recipient,
        send_locked_transfer.queue_name,
        mediated_transfer_message,
    )


def handle_send_directtransfer(
        raiden: RaidenService,
        send_direct_transfer: SendDirectTransfer,
):
    direct_transfer_message = message_from_sendevent(send_direct_transfer, raiden.address)
    raiden.sign(direct_transfer_message)
    raiden.transport.send_async(
        send_direct_transfer.recipient,
        send_direct_transfer.queue_name,
        direct_transfer_message,
    )


def handle_send_revealsecret(
        raiden: RaidenService,
        reveal_secret_event: SendRevealSecret,
):
    reveal_secret_message = message_from_sendevent(reveal_secret_event, raiden.address)
    raiden.sign(reveal_secret_message)
    raiden.transport.send_async(
        reveal_secret_event.recipient,
        reveal_secret_event.queue_name,
        reveal_secret_message,
    )


def handle_send_balanceproof(
        raiden: RaidenService,
        balance_proof_event: SendBalanceProof,
):
    secret_message = message_from_sendevent(balance_proof_event, raiden.address)
    raiden.sign(secret_message)
    raiden.transport.send_async(
        balance_proof_event.recipient,
        balance_proof_event.queue_name,
        secret_message,
    )


def handle_send_secretrequest(
        raiden: RaidenService,
        secret_request_event: SendSecretRequest,
):
    secret_request_message = message_from_sendevent(secret_request_event, raiden.address)
    raiden.sign(secret_request_message)
    raiden.transport.send_async(
        secret_request_event.recipient,
        secret_request_event.queue_name,
        secret_request_message,
    )


def handle_send_refundtransfer(
        raiden: RaidenService,
        refund_transfer_event: SendRefundTransfer,
):
    refund_transfer_message = message_from_sendevent(refund_transfer_event, raiden.address)
    raiden.sign(refund_transfer_message)
    raiden.transport.send_async(
        refund_transfer_event.recipient,
        refund_transfer_event.queue_name,
        refund_transfer_message,
    )


def handle_send_processed(
        raiden: RaidenService,
        processed_event: SendProcessed,
):
    processed_message = message_from_sendevent(processed_event, raiden.address)
    raiden.sign(processed_message)
    raiden.transport.send_async(
        processed_event.recipient,
        processed_event.queue_name,
        processed_message,
    )


def handle_transfersentsuccess(
        raiden: RaidenService,
        transfer_sent_success_event: EventTransferSentSuccess,
):
    for result in raiden.identifier_to_results[transfer_sent_success_event.identifier]:
        result.set(True)

    del raiden.identifier_to_results[transfer_sent_success_event.identifier]


def handle_transfersentfailed(
        raiden: RaidenService,
        transfer_sent_failed_event: EventTransferSentFailed,
):
    for result in raiden.identifier_to_results[transfer_sent_failed_event.identifier]:
        result.set(False)
    del raiden.identifier_to_results[transfer_sent_failed_event.identifier]


def handle_unlockfailed(
        raiden: RaidenService,
        unlock_failed_event: EventUnlockFailed,
):
    # pylint: disable=unused-argument
    log.error(
        'UnlockFailed!',
        secrethash=pex(unlock_failed_event.secrethash),
        reason=unlock_failed_event.reason,
    )


def handle_contract_send_secretreveal(
        raiden: RaidenService,
        channel_close_event: ContractSendSecretReveal,
):
    raiden.default_secret_registry.register_secret(channel_close_event.secret)


def handle_contract_send_channelclose(
        raiden: RaidenService,
        channel_close_event: ContractSendChannelClose,
):
    balance_proof = channel_close_event.balance_proof

    if balance_proof:
        nonce = balance_proof.nonce
        transferred_amount = balance_proof.transferred_amount
        locked_amount = balance_proof.locked_amount
        locksroot = balance_proof.locksroot
        signature = balance_proof.signature
        message_hash = balance_proof.message_hash

    else:
        nonce = 0
        transferred_amount = 0
        locked_amount = 0
        locksroot = b''
        signature = b''
        message_hash = b''

    channel = raiden.chain.netting_channel(channel_close_event.channel_identifier)

    channel.close(
        nonce,
        transferred_amount,
        locked_amount,
        locksroot,
        message_hash,
        signature,
    )


def handle_contract_send_channelclose2(
        raiden: RaidenService,
        channel_close_event: ContractSendChannelClose,
):
    balance_proof = channel_close_event.balance_proof

    if balance_proof:
        nonce = balance_proof.nonce
        balance_hash = balance_proof.balance_hash
        signature = balance_proof.signature
        message_hash = balance_proof.message_hash

    else:
        nonce = 0
        balance_hash = b''
        signature = b''
        message_hash = b''

    channel = raiden.chain.payment_channel(channel_close_event.channel_identifier)

    channel.close(
        nonce,
        balance_hash,
        message_hash,
        signature,
    )


def handle_contract_send_channelupdate(
        raiden: RaidenService,
        channel_update_event: ContractSendChannelUpdateTransfer,
):
    balance_proof = channel_update_event.balance_proof

    if balance_proof:
        channel = raiden.chain.netting_channel(channel_update_event.channel_identifier)
        channel.update_transfer(
            balance_proof.nonce,
            balance_proof.transferred_amount,
            balance_proof.locked_amount,
            balance_proof.locksroot,
            balance_proof.message_hash,
            balance_proof.signature,
        )


def handle_contract_send_channelupdate2(
        raiden: RaidenService,
        channel_update_event: ContractSendChannelUpdateTransfer,
):
    balance_proof = channel_update_event.balance_proof

    if balance_proof:
        channel = raiden.chain.payment_channel(channel_update_event.channel_identifier)

        our_signature = signing_update_data(
            balance_proof,
            raiden.chain.network_id,
            raiden.privkey,
        )

        channel.update_transfer(
            balance_proof.nonce,
            balance_proof.balance_hash,
            balance_proof.message_hash,
            balance_proof.signature,
            our_signature,
        )


def handle_contract_send_channelunlock(
        raiden: RaidenService,
        channel_unlock_event: ContractSendChannelBatchUnlock,
):
    channel = raiden.chain.netting_channel(channel_unlock_event.channel_identifier)
    block_number = raiden.get_block_number()

    for unlock_proof in channel_unlock_event.unlock_proofs:
        lock = Lock.from_bytes(unlock_proof.lock_encoded)

        if lock.expiration < block_number:
            log.error('Lock has expired!', lock=lock)
        else:
            channel.unlock(unlock_proof)


def handle_contract_send_channelunlock2(
        raiden: RaidenService,
        channel_unlock_event: ContractSendChannelBatchUnlock,
):
    channel = raiden.chain.netting_channel(channel_unlock_event.channel_identifier)

    channel.unlock(channel_unlock_event.unlock_proofs)


def handle_contract_send_channelsettle(
        raiden: RaidenService,
        channel_settle_event: ContractSendChannelSettle,
):
    channel = raiden.chain.netting_channel(channel_settle_event.channel_identifier)
    channel.settle()


def handle_contract_send_channelsettle2(
        raiden: RaidenService,
        channel_settle_event: ContractSendChannelSettle,
):
    channel = raiden.chain.payment_channel(channel_settle_event.channel_identifier)
    our_balance_proof = channel_settle_event.our_balance_proof
    partner_balance_proof = channel_settle_event.partner_balance_proof

    channel.settle(
        our_balance_proof.transferred_amount,
        our_balance_proof.locked_amount,
        our_balance_proof.locksroot,
        partner_balance_proof.transferred_amount,
        partner_balance_proof.locked_amount,
        partner_balance_proof.locksroot,
    )


def on_raiden_event(raiden: RaidenService, event: Event):
    # pylint: disable=too-many-branches

    if type(event) == SendLockedTransfer:
        handle_send_lockedtransfer(raiden, event)
    elif type(event) == SendDirectTransfer:
        handle_send_directtransfer(raiden, event)
    elif type(event) == SendRevealSecret:
        handle_send_revealsecret(raiden, event)
    elif type(event) == SendBalanceProof:
        handle_send_balanceproof(raiden, event)
    elif type(event) == SendSecretRequest:
        handle_send_secretrequest(raiden, event)
    elif type(event) == SendRefundTransfer:
        handle_send_refundtransfer(raiden, event)
    elif type(event) == SendProcessed:
        handle_send_processed(raiden, event)
    elif type(event) == EventTransferSentSuccess:
        handle_transfersentsuccess(raiden, event)
    elif type(event) == EventTransferSentFailed:
        handle_transfersentfailed(raiden, event)
    elif type(event) == EventUnlockFailed:
        handle_unlockfailed(raiden, event)
    elif type(event) == ContractSendSecretReveal:
        handle_contract_send_secretreveal(raiden, event)
    elif type(event) == ContractSendChannelClose:
        handle_contract_send_channelclose(raiden, event)
        # handle_contract_send_channelclose2(raiden, event)
    elif type(event) == ContractSendChannelUpdateTransfer:
        handle_contract_send_channelupdate(raiden, event)
        # handle_contract_send_channelupdate2(raiden, event)
    elif type(event) == ContractSendChannelBatchUnlock:
        handle_contract_send_channelunlock(raiden, event)
    elif type(event) == ContractSendChannelSettle:
        handle_contract_send_channelsettle(raiden, event)
        # handle_contract_send_channelsettle2(raiden, event)
    elif type(event) in UNEVENTFUL_EVENTS:
        pass
    else:
        log.error('Unknown event {}'.format(type(event)))
