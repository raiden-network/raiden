import structlog

from raiden.exceptions import ChannelIncorrectStateError
from raiden.messages import message_from_sendevent
from raiden.transfer.architecture import Event
from raiden.transfer.events import (
    ContractSendSecretReveal,
    ContractSendChannelClose,
    ContractSendChannelSettle,
    ContractSendChannelUpdateTransfer,
    ContractSendChannelBatchUnlock,
    EventTransferReceivedInvalidDirectTransfer,
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
    EventTransferReceivedInvalidDirectTransfer,
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
        balance_hash = balance_proof.balance_hash
        signature = balance_proof.signature
        message_hash = balance_proof.message_hash

    else:
        nonce = 0
        balance_hash = b''
        signature = b''
        message_hash = b''

    channel_proxy = raiden.chain.payment_channel(
        token_network_address=channel_close_event.token_network_identifier,
        channel_id=channel_close_event.channel_identifier,
    )

    try:
        channel_proxy.close(
            nonce,
            balance_hash,
            message_hash,
            signature,
        )
    except ChannelIncorrectStateError:
        # This may happen for two reasons:
        # - The channel was also closed by the partner and this transaction
        # lost the race
        # - The ActionCloseChannel was processed in a previous run, and the the
        # node was restarted, so the channel is already closed but the
        # blockchain event to update the local state was not processed yet
        msg = 'Channel with {partner_address} for token {token_address} is already closed'.format(
            partner_address=pex(channel_proxy.participant2),
            token_address=pex(channel_proxy.token_address()),
        )
        log.info(msg)


def handle_contract_send_channelupdate(
        raiden: RaidenService,
        channel_update_event: ContractSendChannelUpdateTransfer,
):
    balance_proof = channel_update_event.balance_proof

    if balance_proof:
        channel = raiden.chain.payment_channel(
            token_network_address=channel_update_event.token_network_identifier,
            channel_id=channel_update_event.channel_identifier,
        )

        our_signature = signing_update_data(
            balance_proof,
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
    channel = raiden.chain.payment_channel(
        channel_unlock_event.token_network_identifier,
        channel_unlock_event.channel_identifier,
    )
    channel.unlock(channel_unlock_event.merkle_treee_leaves)


def handle_contract_send_channelsettle(
        raiden: RaidenService,
        channel_settle_event: ContractSendChannelSettle,
):
    channel = raiden.chain.payment_channel(
        token_network_address=channel_settle_event.token_network_identifier,
        channel_id=channel_settle_event.channel_identifier,
    )
    our_balance_proof = channel_settle_event.our_balance_proof
    partner_balance_proof = channel_settle_event.partner_balance_proof

    if our_balance_proof:
        our_transferred_amount = our_balance_proof.transferred_amount
        our_locked_amount = our_balance_proof.locked_amount
        our_locksroot = our_balance_proof.locksroot
    else:
        our_transferred_amount = 0
        our_locked_amount = 0
        our_locksroot = b''

    if partner_balance_proof:
        partner_transferred_amount = partner_balance_proof.transferred_amount
        partner_locked_amount = partner_balance_proof.locked_amount
        partner_locksroot = partner_balance_proof.locksroot
    else:
        partner_transferred_amount = 0
        partner_locked_amount = 0
        partner_locksroot = b''

    our_max_transferred = our_transferred_amount + our_locked_amount
    partner_max_transferred = partner_transferred_amount + partner_locked_amount

    # The smart contract requires the max transferred of the /first/ balance
    # proof to be /smaller/.
    if our_max_transferred < partner_max_transferred:
        first_transferred_amount = our_transferred_amount
        first_locked_amount = our_locked_amount
        first_locksroot = our_locksroot
        second_transferred_amount = partner_transferred_amount
        second_locked_amount = partner_locked_amount
        second_locksroot = partner_locksroot
    else:
        first_transferred_amount = partner_transferred_amount
        first_locked_amount = partner_locked_amount
        first_locksroot = partner_locksroot
        second_transferred_amount = our_transferred_amount
        second_locked_amount = our_locked_amount
        second_locksroot = our_locksroot

    try:
        channel.settle(
            first_transferred_amount,
            first_locked_amount,
            first_locksroot,
            second_transferred_amount,
            second_locked_amount,
            second_locksroot,
        )
    except ChannelIncorrectStateError:
        # Ignoring the exception as there might
        # be a race condition when both nodes try to settle
        # at the same time.
        pass


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
    elif type(event) == ContractSendChannelUpdateTransfer:
        handle_contract_send_channelupdate(raiden, event)
    elif type(event) == ContractSendChannelBatchUnlock:
        handle_contract_send_channelunlock(raiden, event)
    elif type(event) == ContractSendChannelSettle:
        handle_contract_send_channelsettle(raiden, event)
    elif type(event) in UNEVENTFUL_EVENTS:
        pass
    else:
        log.error('Unknown event {}'.format(type(event)))
