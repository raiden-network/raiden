import structlog
from eth_utils import to_canonical_address, to_checksum_address, to_hex

from raiden.constants import EMPTY_HASH, EMPTY_SIGNATURE, PATH_FINDING_BROADCASTING_ROOM
from raiden.exceptions import ChannelOutdatedError, RaidenUnrecoverableError
from raiden.messages import UpdatePFS, message_from_sendevent
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
from raiden.transfer.utils import (
    get_event_with_balance_proof_by_balance_hash,
    get_event_with_balance_proof_by_locksroot,
    get_state_change_with_balance_proof_by_balance_hash,
    get_state_change_with_balance_proof_by_locksroot,
)
from raiden.transfer.views import get_channelstate_by_token_network_and_partner, state_from_raiden
from raiden.utils import CanonicalIdentifier, pex

# type alias to avoid both circular dependencies and flake8 errors
RaidenService = 'RaidenService'

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name
UNEVENTFUL_EVENTS = (
    EventPaymentReceivedSuccess,
    EventUnlockSuccess,
    EventUnlockClaimFailed,
    EventUnlockClaimSuccess,
    EventInvalidReceivedLockedTransfer,
    EventInvalidReceivedLockExpired,
    EventInvalidReceivedTransferRefund,
    EventInvalidReceivedUnlock,
)

SEND_BALANCE_PROOF_EVENTS = (
    SendBalanceProof,
    SendLockedTransfer,
    SendLockExpired,
    SendRefundTransfer,
)


class RaidenEventHandler:

    def on_raiden_event(self, raiden: RaidenService, event: Event):
        # pylint: disable=too-many-branches
        if type(event) in SEND_BALANCE_PROOF_EVENTS:
            self.update_pfs(raiden, event)

        if type(event) == SendLockExpired:
            self.handle_send_lockexpired(raiden, event)
        elif type(event) == SendLockedTransfer:
            self.handle_send_lockedtransfer(raiden, event)
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

    @staticmethod
    def handle_send_lockexpired(
            raiden: RaidenService,
            send_lock_expired: SendLockExpired,
    ):
        lock_expired_message = message_from_sendevent(send_lock_expired, raiden.address)
        raiden.sign(lock_expired_message)
        raiden.transport.send_async(
            send_lock_expired.queue_identifier,
            lock_expired_message,
        )

    @staticmethod
    def handle_send_lockedtransfer(
            raiden: RaidenService,
            send_locked_transfer: SendLockedTransfer,
    ):
        mediated_transfer_message = message_from_sendevent(send_locked_transfer, raiden.address)
        raiden.sign(mediated_transfer_message)
        raiden.transport.send_async(
            send_locked_transfer.queue_identifier,
            mediated_transfer_message,
        )

    @staticmethod
    def handle_send_secretreveal(
            raiden: RaidenService,
            reveal_secret_event: SendSecretReveal,
    ):
        reveal_secret_message = message_from_sendevent(reveal_secret_event, raiden.address)
        raiden.sign(reveal_secret_message)
        raiden.transport.send_async(
            reveal_secret_event.queue_identifier,
            reveal_secret_message,
        )

    @staticmethod
    def handle_send_balanceproof(
            raiden: RaidenService,
            balance_proof_event: SendBalanceProof,
    ):
        unlock_message = message_from_sendevent(balance_proof_event, raiden.address)
        raiden.sign(unlock_message)
        raiden.transport.send_async(
            balance_proof_event.queue_identifier,
            unlock_message,
        )

    @staticmethod
    def handle_send_secretrequest(
            raiden: RaidenService,
            secret_request_event: SendSecretRequest,
    ):
        secret_request_message = message_from_sendevent(secret_request_event, raiden.address)
        raiden.sign(secret_request_message)
        raiden.transport.send_async(
            secret_request_event.queue_identifier,
            secret_request_message,
        )

    @staticmethod
    def handle_send_refundtransfer(
            raiden: RaidenService,
            refund_transfer_event: SendRefundTransfer,
    ):
        refund_transfer_message = message_from_sendevent(refund_transfer_event, raiden.address)
        raiden.sign(refund_transfer_message)
        raiden.transport.send_async(
            refund_transfer_event.queue_identifier,
            refund_transfer_message,
        )

    @staticmethod
    def handle_send_processed(
            raiden: RaidenService,
            processed_event: SendProcessed,
    ):
        processed_message = message_from_sendevent(processed_event, raiden.address)
        raiden.sign(processed_message)
        raiden.transport.send_async(
            processed_event.queue_identifier,
            processed_message,
        )

    @staticmethod
    def handle_paymentsentsuccess(
            raiden: RaidenService,
            payment_sent_success_event: EventPaymentSentSuccess,
    ):
        target = payment_sent_success_event.target
        payment_identifier = payment_sent_success_event.identifier
        payment_status = raiden.targets_to_identifiers_to_statuses[target].pop(payment_identifier)

        # With the introduction of the lock we should always get
        # here only once per identifier so payment_status should always exist
        # see: https://github.com/raiden-network/raiden/pull/3191
        payment_status.payment_done.set(True)

    @staticmethod
    def handle_paymentsentfailed(
            raiden: RaidenService,
            payment_sent_failed_event: EventPaymentSentFailed,
    ):
        target = payment_sent_failed_event.target
        payment_identifier = payment_sent_failed_event.identifier
        payment_status = raiden.targets_to_identifiers_to_statuses[target].pop(
            payment_identifier,
            None,
        )
        # In the case of a refund transfer the payment fails earlier
        # but the lock expiration will generate a second
        # EventPaymentSentFailed message which we can ignore here
        if payment_status:
            payment_status.payment_done.set(False)

    @staticmethod
    def handle_unlockfailed(
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

    @staticmethod
    def handle_contract_send_secretreveal(
            raiden: RaidenService,
            channel_reveal_secret_event: ContractSendSecretReveal,
    ):
        raiden.default_secret_registry.register_secret(
            secret=channel_reveal_secret_event.secret,
            given_block_identifier=channel_reveal_secret_event.triggered_by_block_hash,
        )

    @staticmethod
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
            balance_hash = EMPTY_HASH
            signature = EMPTY_SIGNATURE
            message_hash = EMPTY_HASH

        channel_proxy = raiden.chain.payment_channel(
            token_network_address=channel_close_event.token_network_identifier,
            channel_id=channel_close_event.channel_identifier,
        )

        channel_proxy.close(
            nonce=nonce,
            balance_hash=balance_hash,
            additional_hash=message_hash,
            signature=signature,
            block_identifier=channel_close_event.triggered_by_block_hash,
        )

    @staticmethod
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

            non_closing_data = pack_balance_proof_update(
                nonce=balance_proof.nonce,
                balance_hash=balance_proof.balance_hash,
                additional_hash=balance_proof.message_hash,
                canonical_identifier=CanonicalIdentifier(
                    chain_identifier=balance_proof.chain_id,
                    token_network_address=balance_proof.token_network_identifier,
                    channel_identifier=balance_proof.channel_identifier,
                ),
                partner_signature=balance_proof.signature,
            )
            our_signature = raiden.signer.sign(data=non_closing_data)

            try:
                channel.update_transfer(
                    nonce=balance_proof.nonce,
                    balance_hash=balance_proof.balance_hash,
                    additional_hash=balance_proof.message_hash,
                    partner_signature=balance_proof.signature,
                    signature=our_signature,
                    block_identifier=channel_update_event.triggered_by_block_hash,
                )
            except ChannelOutdatedError as e:
                log.error(
                    str(e),
                    node=pex(raiden.address),
                )

    @staticmethod
    def handle_contract_send_channelunlock(
            raiden: RaidenService,
            channel_unlock_event: ContractSendChannelBatchUnlock,
    ):
        token_network_identifier = channel_unlock_event.token_network_identifier
        channel_identifier = channel_unlock_event.channel_identifier
        participant = channel_unlock_event.participant
        token_address = channel_unlock_event.token_address
        triggered_by_block_hash = channel_unlock_event.triggered_by_block_hash

        payment_channel: PaymentChannel = raiden.chain.payment_channel(
            token_network_address=token_network_identifier,
            channel_id=channel_identifier,
        )
        token_network: TokenNetwork = payment_channel.token_network

        participants_details = token_network.detail_participants(
            participant1=raiden.address,
            participant2=participant,
            block_identifier=triggered_by_block_hash,
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
            state_change_record = get_state_change_with_balance_proof_by_locksroot(
                storage=raiden.wal.storage,
                chain_id=raiden.chain.network_id,
                token_network_identifier=token_network_identifier,
                channel_identifier=channel_identifier,
                locksroot=partner_locksroot,
                sender=participants_details.partner_details.address,
            )
            state_change_identifier = state_change_record.state_change_identifier
        elif is_our_unlock:
            event_record = get_event_with_balance_proof_by_locksroot(
                storage=raiden.wal.storage,
                chain_id=raiden.chain.network_id,
                token_network_identifier=token_network_identifier,
                channel_identifier=channel_identifier,
                locksroot=our_locksroot.balance_hash,
            )
            state_change_identifier = event_record.state_change_identifier
        else:
            # In the case that someone else sent the unlock we do nothing
            # Check https://github.com/raiden-network/raiden/issues/3152
            # for more details
            log.warning(
                'Onchain unlock already mined',
                token_address=token_address,
                channel_identifier=channel_identifier,
                participant=participant,
            )
            return

        if not state_change_identifier:
            raise RaidenUnrecoverableError(
                f'Failed to find state/event that match current channel locksroots. '
                f'chain_id:{raiden.chain.network_id} '
                f'token:{to_checksum_address(token_address)} '
                f'token_network:{to_checksum_address(token_network_identifier)} '
                f'channel:{channel_identifier} '
                f'participant:{to_checksum_address(participant)} '
                f'our_locksroot:{to_hex(our_locksroot)} '
                f'our_balance_hash:{to_hex(our_details.balance_hash)} '
                f'partner_locksroot:{to_hex(partner_locksroot)} '
                f'partner_balancehash:{to_hex(partner_details.balance_hash)} ',
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
            payment_channel.unlock(
                merkle_tree_leaves=merkle_tree_leaves,
                block_identifier=triggered_by_block_hash,
            )
        except ChannelOutdatedError as e:
            log.error(
                str(e),
                node=pex(raiden.address),
            )

    @staticmethod
    def handle_contract_send_channelsettle(
            raiden: RaidenService,
            channel_settle_event: ContractSendChannelSettle,
    ):
        chain_id = raiden.chain.network_id
        token_network_identifier = channel_settle_event.token_network_identifier
        channel_identifier = channel_settle_event.channel_identifier
        triggered_by_block_hash = channel_settle_event.triggered_by_block_hash

        payment_channel: PaymentChannel = raiden.chain.payment_channel(
            token_network_address=channel_settle_event.token_network_identifier,
            channel_id=channel_settle_event.channel_identifier,
        )

        token_network_proxy: TokenNetwork = payment_channel.token_network
        participants_details = token_network_proxy.detail_participants(
            participant1=payment_channel.participant1,
            participant2=payment_channel.participant2,
            block_identifier=triggered_by_block_hash,
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
            event_record = get_event_with_balance_proof_by_balance_hash(
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
            state_change_record = get_state_change_with_balance_proof_by_balance_hash(
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
            transferred_amount=our_transferred_amount,
            locked_amount=our_locked_amount,
            locksroot=our_locksroot,
            partner_transferred_amount=partner_transferred_amount,
            partner_locked_amount=partner_locked_amount,
            partner_locksroot=partner_locksroot,
            block_identifier=triggered_by_block_hash,
        )

    @staticmethod
    def update_pfs(raiden: RaidenService, event: Event):
        channel_state = get_channelstate_by_token_network_and_partner(
            chain_state=state_from_raiden(raiden),
            token_network_id=to_canonical_address(
                event.balance_proof.token_network_identifier,
            ),
            partner_address=to_canonical_address(event.recipient),
        )
        error_msg = 'tried to send a balance proof in non-existant channel '
        f'token_network_address: {pex(event.balance_proof.token_network_identifier)} '
        f'recipient: {pex(event.recipient)}'
        assert channel_state is not None, error_msg

        msg = UpdatePFS.from_balance_proof(
            balance_proof=event.balance_proof,
            reveal_timeout=channel_state.reveal_timeout,
        )
        msg.sign(raiden.signer)
        raiden.transport.send_global(PATH_FINDING_BROADCASTING_ROOM, msg)
        log.debug(
            'sent a PFS Update',
            balance_proof=event.balance_proof,
            recipient=event.recipient,
        )
