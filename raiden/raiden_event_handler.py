import structlog

from raiden.constants import EMPTY_HASH, EMPTY_SIGNATURE
from raiden.exceptions import ChannelOutdatedError
from raiden.messages import message_from_sendevent
from raiden.network.proxies import PaymentChannel, TokenNetwork
from raiden.storage.restore import channel_state_until_balance_hash
from raiden.transfer.architecture import Event
from raiden.transfer.balance_proof import pack_balance_proof_update
from raiden.transfer.channel import get_batch_unlock
from raiden.transfer.events import (
    ContractSendChannelBatchUnlock,
    ContractSendChannelClose,
    ContractSendChannelSettle,
    ContractSendChannelUpdateTransfer,
    ContractSendSecretReveal,
    EventPaymentReceivedSuccess,
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
    EventTransferReceivedInvalidDirectTransfer,
    SendDirectTransfer,
    SendProcessed,
)
from raiden.transfer.mediated_transfer.events import (
    EventUnlockClaimFailed,
    EventUnlockClaimSuccess,
    EventUnlockFailed,
    EventUnlockSuccess,
    SendBalanceProof,
    SendLockedTransfer,
    SendLockExpired,
    SendRefundTransfer,
    SendSecretRequest,
    SendSecretReveal,
)
from raiden.utils import pex
from raiden.utils.serialization import serialize_bytes
from raiden_libs.utils.signing import eth_sign

# type alias to avoid both circular dependencies and flake8 errors
RaidenService = 'RaidenService'

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name
UNEVENTFUL_EVENTS = (
    EventTransferReceivedInvalidDirectTransfer,
    EventPaymentReceivedSuccess,
    EventUnlockSuccess,
    EventUnlockClaimFailed,
    EventUnlockClaimSuccess,
)


class RaidenEventHandler:
    def on_raiden_event(self, raiden: RaidenService, event: Event):
        # pylint: disable=too-many-branches

        if type(event) == SendLockExpired:
            self.handle_send_lockexpired(raiden, event)
        elif type(event) == SendLockedTransfer:
            self.handle_send_lockedtransfer(raiden, event)
        elif type(event) == SendDirectTransfer:
            self.handle_send_directtransfer(raiden, event)
        elif type(event) == SendSecretReveal:
            self.handle_send_revealsecret(raiden, event)
        elif type(event) == SendBalanceProof:
            self.handle_send_balanceproof(raiden, event)
        elif type(event) == SendSecretRequest:
            self.handle_send_secretrequest(raiden, event)
        elif type(event) == SendRefundTransfer:
            self.handle_send_refundtransfer(raiden, event)
        elif type(event) == SendProcessed:
            self.handle_send_processed(raiden, event)
        elif type(event) == EventPaymentSentSuccess:
            self.handle_paymentsentsuccess(raiden, event)
        elif type(event) == EventPaymentSentFailed:
            self.handle_paymentsentfailed(raiden, event)
        elif type(event) == EventUnlockFailed:
            self.handle_unlockfailed(raiden, event)
        elif type(event) == ContractSendSecretReveal:
            self.handle_contract_send_secretreveal(raiden, event)
        elif type(event) == ContractSendChannelClose:
            self.handle_contract_send_channelclose(raiden, event)
        elif type(event) == ContractSendChannelUpdateTransfer:
            self.handle_contract_send_channelupdate(raiden, event)
        elif type(event) == ContractSendChannelBatchUnlock:
            self.handle_contract_send_channelunlock(raiden, event)
        elif type(event) == ContractSendChannelSettle:
            self.handle_contract_send_channelsettle(raiden, event)
        elif type(event) in UNEVENTFUL_EVENTS:
            pass
        else:
            log.error('Unknown event {}'.format(type(event)))

    def handle_send_lockexpired(
            self,
            raiden: RaidenService,
            send_lock_expired: SendLockExpired,
    ):
        lock_expired_message = message_from_sendevent(send_lock_expired, raiden.address)
        raiden.sign(lock_expired_message)
        raiden.transport.send_async(
            send_lock_expired.queue_identifier,
            lock_expired_message,
        )

    def handle_send_lockedtransfer(
            self,
            raiden: RaidenService,
            send_locked_transfer: SendLockedTransfer,
    ):
        mediated_transfer_message = message_from_sendevent(send_locked_transfer, raiden.address)
        raiden.sign(mediated_transfer_message)
        raiden.transport.send_async(
            send_locked_transfer.queue_identifier,
            mediated_transfer_message,
        )

    def handle_send_directtransfer(
            self,
            raiden: RaidenService,
            send_direct_transfer: SendDirectTransfer,
    ):
        direct_transfer_message = message_from_sendevent(send_direct_transfer, raiden.address)
        raiden.sign(direct_transfer_message)
        raiden.transport.send_async(
            send_direct_transfer.queue_identifier,
            direct_transfer_message,
        )

    def handle_send_revealsecret(
            self,
            raiden: RaidenService,
            reveal_secret_event: SendSecretReveal,
    ):
        reveal_secret_message = message_from_sendevent(reveal_secret_event, raiden.address)
        raiden.sign(reveal_secret_message)
        raiden.transport.send_async(
            reveal_secret_event.queue_identifier,
            reveal_secret_message,
        )

    def handle_send_balanceproof(
            self,
            raiden: RaidenService,
            balance_proof_event: SendBalanceProof,
    ):
        secret_message = message_from_sendevent(balance_proof_event, raiden.address)
        raiden.sign(secret_message)
        raiden.transport.send_async(
            balance_proof_event.queue_identifier,
            secret_message,
        )

    def handle_send_secretrequest(
            self,
            raiden: RaidenService,
            secret_request_event: SendSecretRequest,
    ):
        secret_request_message = message_from_sendevent(secret_request_event, raiden.address)
        raiden.sign(secret_request_message)
        raiden.transport.send_async(
            secret_request_event.queue_identifier,
            secret_request_message,
        )

    def handle_send_refundtransfer(
            self,
            raiden: RaidenService,
            refund_transfer_event: SendRefundTransfer,
    ):
        refund_transfer_message = message_from_sendevent(refund_transfer_event, raiden.address)
        raiden.sign(refund_transfer_message)
        raiden.transport.send_async(
            refund_transfer_event.queue_identifier,
            refund_transfer_message,
        )

    def handle_send_processed(
            self,
            raiden: RaidenService,
            processed_event: SendProcessed,
    ):
        processed_message = message_from_sendevent(processed_event, raiden.address)
        raiden.sign(processed_message)
        raiden.transport.send_async(
            processed_event.queue_identifier,
            processed_message,
        )

    def handle_paymentsentsuccess(
            self,
            raiden: RaidenService,
            payment_sent_success_event: EventPaymentSentSuccess,
    ):
        assert payment_sent_success_event.identifier in raiden.identifier_to_results

        result = raiden.identifier_to_results[payment_sent_success_event.identifier]
        result.set(True)
        del raiden.identifier_to_results[payment_sent_success_event.identifier]

    def handle_paymentsentfailed(
            self,
            raiden: RaidenService,
            payment_sent_failed_event: EventPaymentSentFailed,
    ):
        assert payment_sent_failed_event.identifier in raiden.identifier_to_results

        result = raiden.identifier_to_results[payment_sent_failed_event.identifier]
        result.set(False)
        del raiden.identifier_to_results[payment_sent_failed_event.identifier]

    def handle_unlockfailed(
            self,
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
            self,
            raiden: RaidenService,
            channel_close_event: ContractSendSecretReveal,
    ):
        raiden.default_secret_registry.register_secret(channel_close_event.secret)

    def handle_contract_send_channelclose(
            self,
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
            balance_hash = EMPTY_HASH
            signature = EMPTY_SIGNATURE
            message_hash = EMPTY_HASH

        channel_proxy = raiden.chain.payment_channel(
            token_network_address=channel_close_event.token_network_identifier,
            channel_id=channel_close_event.channel_identifier,
        )

        channel_proxy.close(
            nonce,
            balance_hash,
            message_hash,
            signature,
        )

    def handle_contract_send_channelupdate(
            self,
            raiden: RaidenService,
            channel_update_event: ContractSendChannelUpdateTransfer,
    ):
        balance_proof = channel_update_event.balance_proof

        if balance_proof:
            channel = raiden.chain.payment_channel(
                token_network_address=channel_update_event.token_network_identifier,
                channel_id=channel_update_event.channel_identifier,
            )

            non_closing_data = pack_balance_proof_update(
                nonce=balance_proof.nonce,
                balance_hash=balance_proof.balance_hash,
                additional_hash=balance_proof.message_hash,
                channel_identifier=balance_proof.channel_identifier,
                token_network_identifier=balance_proof.token_network_identifier,
                chain_id=balance_proof.chain_id,
                partner_signature=balance_proof.signature,
            )
            our_signature = eth_sign(privkey=raiden.privkey, data=non_closing_data)

            try:
                channel.update_transfer(
                    balance_proof.nonce,
                    balance_proof.balance_hash,
                    balance_proof.message_hash,
                    balance_proof.signature,
                    our_signature,
                )
            except ChannelOutdatedError as e:
                log.error(str(e))

    def handle_contract_send_channelunlock(
            self,
            raiden: RaidenService,
            channel_unlock_event: ContractSendChannelBatchUnlock,
    ):
        payment_channel: PaymentChannel = raiden.chain.payment_channel(
            channel_unlock_event.token_network_identifier,
            channel_unlock_event.channel_identifier,
        )
        token_network: TokenNetwork = payment_channel.token_network

        # Fetch on-chain balance hashes for both participants
        participants_details = token_network.details_participants(
            raiden.address,
            channel_unlock_event.partner,
            channel_unlock_event.channel_identifier,
        )

        # Replay state changes until a channel state is reached where
        # this channel state has the participants balance hash.
        restored_channel_state = channel_state_until_balance_hash(
            raiden=raiden,
            token_address=channel_unlock_event.token_address,
            channel_identifier=channel_unlock_event.channel_identifier,
            target_balance_hash=participants_details.partner_details.balance_hash,
        )

        if not restored_channel_state:
            log.error('Could not find channel state with partner balance hash {}'.format(
                pex(participants_details.partner_details.balance_hash),
            ))
            return

        # Compute merkle tree leaves from partner state
        partner_state = restored_channel_state.partner_state
        merkle_tree_leaves = get_batch_unlock(partner_state)

        try:
            payment_channel.unlock(
                restored_channel_state.identifier,
                channel_unlock_event.partner,
                merkle_tree_leaves,
            )
        except ChannelOutdatedError as e:
            log.error(str(e))

    def handle_contract_send_channelsettle(
            self,
            raiden: RaidenService,
            channel_settle_event: ContractSendChannelSettle,
    ):
        payment_channel: PaymentChannel = raiden.chain.payment_channel(
            token_network_address=channel_settle_event.token_network_identifier,
            channel_id=channel_settle_event.channel_identifier,
        )

        token_network_proxy: TokenNetwork = payment_channel.token_network
        # Fetch on-chain balance hashes for both participants
        participants_details = token_network_proxy.detail_participants(
            participant1=payment_channel.participant1,
            participant2=payment_channel.participant2,
            channel_identifier=channel_settle_event.channel_identifier,
        )

        # Query state changes which have the on-chain
        # balance hash and use the balance proofs from those states.
        storage = raiden.wal.storage
        our_state_changes = storage.get_state_changes_by_data_field(
            'balance_hash',
            serialize_bytes(participants_details.our_details.balance_hash),
        )

        partner_state_changes = storage.get_state_changes_by_data_field(
            'balance_hash',
            serialize_bytes(participants_details.partner_details.balance_hash),
        )

        our_balance_proof = None
        partner_balance_proof = None

        if our_state_changes:
            our_balance_proof = our_state_changes[0].balance_proof

        if partner_state_changes:
            partner_balance_proof = partner_state_changes[0].balance_proof

        our_balance_hash = participants_details.our_details.balance_hash
        if our_balance_proof and our_balance_hash != EMPTY_HASH:
            our_transferred_amount = our_balance_proof.transferred_amount
            our_locked_amount = our_balance_proof.locked_amount
            our_locksroot = our_balance_proof.locksroot
        else:
            our_transferred_amount = 0
            our_locked_amount = 0
            our_locksroot = EMPTY_HASH

        partner_balance_hash = participants_details.partner_details.balance_hash
        if partner_balance_proof and partner_balance_hash != EMPTY_HASH:
            partner_transferred_amount = partner_balance_proof.transferred_amount
            partner_locked_amount = partner_balance_proof.locked_amount
            partner_locksroot = partner_balance_proof.locksroot
        else:
            partner_transferred_amount = 0
            partner_locked_amount = 0
            partner_locksroot = EMPTY_HASH

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

        payment_channel.settle(
            first_transferred_amount,
            first_locked_amount,
            first_locksroot,
            second_transferred_amount,
            second_locked_amount,
            second_locksroot,
        )
