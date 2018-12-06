import structlog
from eth_utils import to_checksum_address, to_hex

from raiden.constants import EMPTY_HASH, EMPTY_SIGNATURE
from raiden.exceptions import ChannelOutdatedError, RaidenUnrecoverableError
from raiden.messages import message_from_sendevent
from raiden.network.proxies import PaymentChannel, TokenNetwork
from raiden.storage.restore import channel_state_until_state_change
from raiden.transfer.architecture import Event
from raiden.transfer.balance_proof import pack_balance_proof_update
from raiden.transfer.channel import get_batch_unlock
from raiden.transfer.events import (
    ContractSendChannelBatchUnlock,
    ContractSendChannelClose,
    ContractSendChannelSettle,
    ContractSendChannelUpdateTransfer,
    ContractSendSecretReveal,
    EventInvalidReceivedLockedTransfer,
    EventInvalidReceivedLockExpired,
    EventInvalidReceivedTransferRefund,
    EventInvalidReceivedUnlock,
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
from raiden.transfer.utils import get_event_with_balance_proof, get_state_change_with_balance_proof
from raiden.utils import pex
from raiden.utils.signing import eth_sign

# type alias to avoid both circular dependencies and flake8 errors
RaidenService = 'RaidenService'

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name
UNEVENTFUL_EVENTS = (
    EventTransferReceivedInvalidDirectTransfer,
    EventPaymentReceivedSuccess,
    EventUnlockSuccess,
    EventUnlockClaimFailed,
    EventUnlockClaimSuccess,
    EventInvalidReceivedLockedTransfer,
    EventInvalidReceivedLockExpired,
    EventInvalidReceivedTransferRefund,
    EventInvalidReceivedUnlock,
)


class RaidenEventHandler:
    # pylint: disable=no-self-use

    def on_raiden_event(self, raiden: RaidenService, event: Event):
        # pylint: disable=too-many-branches

        if type(event) == SendLockExpired:
            self.handle_send_lockexpired(raiden, event)
        elif type(event) == SendLockedTransfer:
            self.handle_send_lockedtransfer(raiden, event)
        elif type(event) == SendDirectTransfer:
            self.handle_send_directtransfer(raiden, event)
        elif type(event) == SendSecretReveal:
            self.handle_send_secretreveal(raiden, event)
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
            log.error(
                'Unknown event',
                event_type=str(type(event)),
                node=pex(raiden.address),
            )

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

    def handle_send_secretreveal(
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
        target = payment_sent_success_event.target
        payment_status = raiden.targets_to_identifiers_to_statuses[target].pop(
            payment_sent_success_event.identifier,
            None,
        )
        assert payment_status is not None
        payment_status.payment_done.set(True)

    def handle_paymentsentfailed(
            self,
            raiden: RaidenService,
            payment_sent_failed_event: EventPaymentSentFailed,
    ):
        target = payment_sent_failed_event.target
        payment_status = raiden.targets_to_identifiers_to_statuses[target].pop(
            payment_sent_failed_event.identifier,
            None,
        )
        assert payment_status is not None
        payment_status.payment_done.set(False)

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
            node=pex(raiden.address),
        )

    def handle_contract_send_secretreveal(
            self,
            raiden: RaidenService,
            channel_reveal_secret_event: ContractSendSecretReveal,
    ):
        raiden.default_secret_registry.register_secret(channel_reveal_secret_event.secret)

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
                    nonce=balance_proof.nonce,
                    balance_hash=balance_proof.balance_hash,
                    additional_hash=balance_proof.message_hash,
                    partner_signature=balance_proof.signature,
                    signature=our_signature,
                )
            except ChannelOutdatedError as e:
                log.error(
                    str(e),
                    node=pex(raiden.address),
                )

    def handle_contract_send_channelunlock(
            self,
            raiden: RaidenService,
            channel_unlock_event: ContractSendChannelBatchUnlock,
    ):
        token_network_identifier = channel_unlock_event.token_network_identifier
        channel_identifier = channel_unlock_event.channel_identifier
        participant = channel_unlock_event.participant
        token_address = channel_unlock_event.token_address

        payment_channel: PaymentChannel = raiden.chain.payment_channel(
            token_network_address=token_network_identifier,
            channel_id=channel_identifier,
        )
        token_network: TokenNetwork = payment_channel.token_network

        participants_details = token_network.detail_participants(
            participant1=raiden.address,
            participant2=participant,
            channel_identifier=channel_identifier,
        )

        our_details = participants_details.our_details
        our_locksroot = our_details.locksroot

        partner_details = participants_details.partner_details
        partner_locksroot = partner_details.locksroot

        is_partner_unlock = (
            partner_details.address == participant and
            partner_locksroot != EMPTY_HASH
        )
        is_our_unlock = (
            our_details.address == participant and
            our_locksroot != EMPTY_HASH
        )

        if is_partner_unlock:
            state_change_record = get_state_change_with_balance_proof(
                storage=raiden.wal.storage,
                chain_id=raiden.chain.network_id,
                token_network_identifier=token_network_identifier,
                channel_identifier=channel_identifier,
                balance_hash=partner_details.balance_hash,
                sender=participants_details.partner_details.address,
            )
            state_change_identifier = state_change_record.state_change_identifier
        elif is_our_unlock:
            event_record = get_event_with_balance_proof(
                storage=raiden.wal.storage,
                chain_id=raiden.chain.network_id,
                token_network_identifier=token_network_identifier,
                channel_identifier=channel_identifier,
                balance_hash=our_details.balance_hash,
            )
            state_change_identifier = event_record.state_change_identifier
        else:
            state_change_identifier = 0

        if not state_change_identifier:
            raise RaidenUnrecoverableError(
                f'Failed to find state/event that match current channel locksroots. '
                f'token:{to_checksum_address(token_address)} '
                f'token_network:{to_checksum_address(token_network_identifier)} '
                f'channel:{channel_identifier} '
                f'participant:{to_checksum_address(participant)} '
                f'our_locksroot:{to_hex(our_locksroot)} '
                f'partner_locksroot:{to_hex(partner_locksroot)} ',
            )

        # Replay state changes until a channel state is reached where
        # this channel state has the participants balance hash.
        restored_channel_state = channel_state_until_state_change(
            raiden=raiden,
            payment_network_identifier=raiden.default_registry.address,
            token_address=token_address,
            channel_identifier=channel_identifier,
            state_change_identifier=state_change_identifier,
        )

        our_state = restored_channel_state.our_state
        partner_state = restored_channel_state.partner_state
        if partner_state.address == participant:
            merkle_tree_leaves = get_batch_unlock(partner_state)
        elif our_state.address == participant:
            merkle_tree_leaves = get_batch_unlock(our_state)

        try:
            payment_channel.unlock(merkle_tree_leaves)
        except ChannelOutdatedError as e:
            log.error(
                str(e),
                node=pex(raiden.address),
            )

    def handle_contract_send_channelsettle(
            self,
            raiden: RaidenService,
            channel_settle_event: ContractSendChannelSettle,
    ):
        chain_id = raiden.chain.network_id
        token_network_identifier = channel_settle_event.token_network_identifier
        channel_identifier = channel_settle_event.channel_identifier

        payment_channel: PaymentChannel = raiden.chain.payment_channel(
            token_network_address=channel_settle_event.token_network_identifier,
            channel_id=channel_settle_event.channel_identifier,
        )

        token_network_proxy: TokenNetwork = payment_channel.token_network
        participants_details = token_network_proxy.detail_participants(
            participant1=payment_channel.participant1,
            participant2=payment_channel.participant2,
            channel_identifier=channel_settle_event.channel_identifier,
        )

        our_details = participants_details.our_details
        partner_details = participants_details.partner_details

        log_details = {
            'chain_id': chain_id,
            'token_network_identifier': token_network_identifier,
            'channel_identifier': channel_identifier,
            'node': pex(raiden.address),
            'partner': to_checksum_address(partner_details.address),
            'our_deposit': our_details.deposit,
            'our_withdrawn': our_details.withdrawn,
            'our_is_closer': our_details.is_closer,
            'our_balance_hash': to_hex(our_details.balance_hash),
            'our_nonce': our_details.nonce,
            'our_locksroot': to_hex(our_details.locksroot),
            'our_locked_amount': our_details.locked_amount,
            'partner_deposit': partner_details.deposit,
            'partner_withdrawn': partner_details.withdrawn,
            'partner_is_closer': partner_details.is_closer,
            'partner_balance_hash': to_hex(partner_details.balance_hash),
            'partner_nonce': partner_details.nonce,
            'partner_locksroot': to_hex(partner_details.locksroot),
            'partner_locked_amount': partner_details.locked_amount,
        }

        if our_details.balance_hash != EMPTY_HASH:
            event_record = get_event_with_balance_proof(
                storage=raiden.wal.storage,
                chain_id=chain_id,
                token_network_identifier=token_network_identifier,
                channel_identifier=channel_identifier,
                balance_hash=our_details.balance_hash,
            )

            if event_record.data is None:
                log.critical(
                    'our balance proof not found',
                    **log_details,
                )
                raise RaidenUnrecoverableError(
                    'Our balance proof could not be found in the database',
                )

            our_balance_proof = event_record.data.balance_proof
            our_transferred_amount = our_balance_proof.transferred_amount
            our_locked_amount = our_balance_proof.locked_amount
            our_locksroot = our_balance_proof.locksroot
        else:
            our_transferred_amount = 0
            our_locked_amount = 0
            our_locksroot = EMPTY_HASH

        if partner_details.balance_hash != EMPTY_HASH:
            state_change_record = get_state_change_with_balance_proof(
                storage=raiden.wal.storage,
                chain_id=chain_id,
                token_network_identifier=token_network_identifier,
                channel_identifier=channel_identifier,
                balance_hash=partner_details.balance_hash,
                sender=participants_details.partner_details.address,
            )
            if state_change_record.data is None:
                log.critical(
                    'partner balance proof not found',
                    **log_details,
                )
                raise RaidenUnrecoverableError(
                    'Partner balance proof could not be found in the database',
                )

            partner_balance_proof = state_change_record.data.balance_proof
            partner_transferred_amount = partner_balance_proof.transferred_amount
            partner_locked_amount = partner_balance_proof.locked_amount
            partner_locksroot = partner_balance_proof.locksroot
        else:
            partner_transferred_amount = 0
            partner_locked_amount = 0
            partner_locksroot = EMPTY_HASH

        payment_channel.settle(
            our_transferred_amount,
            our_locked_amount,
            our_locksroot,
            partner_transferred_amount,
            partner_locked_amount,
            partner_locksroot,
        )
