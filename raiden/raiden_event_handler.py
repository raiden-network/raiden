from typing import TYPE_CHECKING

import structlog
from eth_utils import to_checksum_address, to_hex

from raiden.constants import EMPTY_HASH, EMPTY_SIGNATURE
from raiden.exceptions import ChannelOutdatedError, RaidenUnrecoverableError
from raiden.messages import message_from_sendevent
from raiden.network.proxies.payment_channel import PaymentChannel
from raiden.network.proxies.token_network import TokenNetwork
from raiden.storage.restore import channel_state_until_state_change
from raiden.transfer.architecture import Event
from raiden.transfer.balance_proof import pack_balance_proof_update
from raiden.transfer.channel import get_batch_unlock, get_batch_unlock_gain
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
from raiden.transfer.state import NettingChannelEndState
from raiden.transfer.utils import (
    get_event_with_balance_proof_by_balance_hash,
    get_event_with_balance_proof_by_locksroot,
    get_state_change_with_balance_proof_by_balance_hash,
    get_state_change_with_balance_proof_by_locksroot,
)
from raiden.transfer.views import get_channelstate_by_token_network_and_partner, state_from_raiden
from raiden.utils import CanonicalIdentifier, pex
from raiden.utils.typing import Address

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.raiden_service import RaidenService

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


def unlock(
        raiden: 'RaidenService',
        payment_channel: PaymentChannel,
        end_state: NettingChannelEndState,
        participant: Address,
        partner: Address,
) -> None:
    merkle_tree_leaves = get_batch_unlock(end_state)

    try:
        payment_channel.unlock(
            participant=participant,
            partner=partner,
            merkle_tree_leaves=merkle_tree_leaves,
        )
    except ChannelOutdatedError as e:
        log.error(
            str(e),
            node=pex(raiden.address),
        )


class RaidenEventHandler:

    def on_raiden_event(self, raiden: 'RaidenService', event: Event):
        # pylint: disable=too-many-branches
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
            raiden: 'RaidenService',
            send_lock_expired: SendLockExpired,
    ):
        lock_expired_message = message_from_sendevent(send_lock_expired)
        raiden.sign(lock_expired_message)
        raiden.transport.send_async(
            send_lock_expired.queue_identifier,
            lock_expired_message,
        )

    @staticmethod
    def handle_send_lockedtransfer(
            raiden: 'RaidenService',
            send_locked_transfer: SendLockedTransfer,
    ):
        mediated_transfer_message = message_from_sendevent(send_locked_transfer)
        raiden.sign(mediated_transfer_message)
        raiden.transport.send_async(
            send_locked_transfer.queue_identifier,
            mediated_transfer_message,
        )

    @staticmethod
    def handle_send_secretreveal(
            raiden: 'RaidenService',
            reveal_secret_event: SendSecretReveal,
    ):
        reveal_secret_message = message_from_sendevent(reveal_secret_event)
        raiden.sign(reveal_secret_message)
        raiden.transport.send_async(
            reveal_secret_event.queue_identifier,
            reveal_secret_message,
        )

    @staticmethod
    def handle_send_balanceproof(
            raiden: 'RaidenService',
            balance_proof_event: SendBalanceProof,
    ):
        unlock_message = message_from_sendevent(balance_proof_event)
        raiden.sign(unlock_message)
        raiden.transport.send_async(
            balance_proof_event.queue_identifier,
            unlock_message,
        )

    @staticmethod
    def handle_send_secretrequest(
            raiden: 'RaidenService',
            secret_request_event: SendSecretRequest,
    ):
        secret_request_message = message_from_sendevent(secret_request_event)
        raiden.sign(secret_request_message)
        raiden.transport.send_async(
            secret_request_event.queue_identifier,
            secret_request_message,
        )

    @staticmethod
    def handle_send_refundtransfer(
            raiden: 'RaidenService',
            refund_transfer_event: SendRefundTransfer,
    ):
        refund_transfer_message = message_from_sendevent(refund_transfer_event)
        raiden.sign(refund_transfer_message)
        raiden.transport.send_async(
            refund_transfer_event.queue_identifier,
            refund_transfer_message,
        )

    @staticmethod
    def handle_send_processed(
            raiden: 'RaidenService',
            processed_event: SendProcessed,
    ):
        processed_message = message_from_sendevent(processed_event)
        raiden.sign(processed_message)
        raiden.transport.send_async(
            processed_event.queue_identifier,
            processed_message,
        )

    @staticmethod
    def handle_paymentsentsuccess(
            raiden: 'RaidenService',
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
            raiden: 'RaidenService',
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
            raiden: 'RaidenService',
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
            raiden: 'RaidenService',
            channel_reveal_secret_event: ContractSendSecretReveal,
    ):
        raiden.default_secret_registry.register_secret(
            secret=channel_reveal_secret_event.secret,
            given_block_identifier=channel_reveal_secret_event.triggered_by_block_hash,
        )

    @staticmethod
    def handle_contract_send_channelclose(
            raiden: 'RaidenService',
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
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=state_from_raiden(raiden).chain_id,
                token_network_address=channel_close_event.token_network_identifier,
                channel_identifier=channel_close_event.channel_identifier,
            ),
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
            raiden: 'RaidenService',
            channel_update_event: ContractSendChannelUpdateTransfer,
    ):
        balance_proof = channel_update_event.balance_proof

        if balance_proof:
            canonical_identifier = balance_proof.canonical_identifier
            channel = raiden.chain.payment_channel(
                canonical_identifier=canonical_identifier,
            )

            non_closing_data = pack_balance_proof_update(
                nonce=balance_proof.nonce,
                balance_hash=balance_proof.balance_hash,
                additional_hash=balance_proof.message_hash,
                canonical_identifier=canonical_identifier,
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
            raiden: 'RaidenService',
            channel_unlock_event: ContractSendChannelBatchUnlock,
    ):
        token_network_identifier = channel_unlock_event.token_network_identifier
        channel_identifier = channel_unlock_event.channel_identifier
        canonical_identifier = CanonicalIdentifier(
            chain_identifier=raiden.chain.network_id,
            token_network_address=token_network_identifier,
            channel_identifier=channel_identifier,
        )
        participant = channel_unlock_event.participant
        token_address = channel_unlock_event.token_address

        payment_channel: PaymentChannel = raiden.chain.payment_channel(
            canonical_identifier=canonical_identifier,
        )

        channel_state = get_channelstate_by_token_network_and_partner(
            chain_state=state_from_raiden(raiden),
            token_network_id=token_network_identifier,
            partner_address=participant,
        )

        if not channel_state:
            # channel was cleaned up already due to an unlock
            raise RaidenUnrecoverableError(
                f'Failed to find channel state with partner:'
                f'{to_checksum_address(participant)}, token_network:pex(token_network_identifier)',
            )

        our_address = channel_state.our_state.address
        our_locksroot = channel_state.our_state.onchain_locksroot

        partner_address = channel_state.partner_state.address
        partner_locksroot = channel_state.partner_state.onchain_locksroot

        # we want to unlock because there are on-chain unlocked locks
        search_events = our_locksroot != EMPTY_HASH
        # we want to unlock, because there are unlocked/unclaimed locks
        search_state_changes = partner_locksroot != EMPTY_HASH

        if not search_events and not search_state_changes:
            # In the case that someone else sent the unlock we do nothing
            # Check https://github.com/raiden-network/raiden/issues/3152
            # for more details
            log.warning(
                'Onchain unlock already mined',
                token_address=token_address,
                channel_identifier=canonical_identifier.channel_identifier,
                participant=participant,
            )
            return

        if search_state_changes:
            state_change_record = get_state_change_with_balance_proof_by_locksroot(
                storage=raiden.wal.storage,
                canonical_identifier=canonical_identifier,
                locksroot=partner_locksroot,
                sender=partner_address,
            )
            state_change_identifier = state_change_record.state_change_identifier

            if not state_change_identifier:
                raise RaidenUnrecoverableError(
                    f'Failed to find state that matches the current channel locksroots. '
                    f'chain_id:{raiden.chain.network_id} '
                    f'token:{to_checksum_address(token_address)} '
                    f'token_network:{to_checksum_address(token_network_identifier)} '
                    f'channel:{channel_identifier} '
                    f'participant:{to_checksum_address(participant)} '
                    f'our_locksroot:{to_hex(our_locksroot)} '
                    f'partner_locksroot:{to_hex(partner_locksroot)} ',
                )

            restored_channel_state = channel_state_until_state_change(
                raiden=raiden,
                payment_network_identifier=raiden.default_registry.address,
                token_address=token_address,
                channel_identifier=channel_identifier,
                state_change_identifier=state_change_identifier,
            )

            gain = get_batch_unlock_gain(
                restored_channel_state,
            )

            skip_unlock = (
                restored_channel_state.partner_state.address == participant and
                gain.from_partner_locks == 0
            )
            if not skip_unlock:
                unlock(
                    raiden=raiden,
                    payment_channel=payment_channel,
                    end_state=restored_channel_state.partner_state,
                    participant=our_address,
                    partner=partner_address,
                )

        if search_events:
            event_record = get_event_with_balance_proof_by_locksroot(
                storage=raiden.wal.storage,
                canonical_identifier=canonical_identifier,
                locksroot=our_locksroot,
                recipient=partner_address,
            )
            state_change_identifier = event_record.state_change_identifier

            if not state_change_identifier:
                raise RaidenUnrecoverableError(
                    f'Failed to find event that match current channel locksroots. '
                    f'chain_id:{raiden.chain.network_id} '
                    f'token:{to_checksum_address(token_address)} '
                    f'token_network:{to_checksum_address(token_network_identifier)} '
                    f'channel:{channel_identifier} '
                    f'participant:{to_checksum_address(participant)} '
                    f'our_locksroot:{to_hex(our_locksroot)} '
                    f'partner_locksroot:{to_hex(partner_locksroot)} ',
                )

            restored_channel_state = channel_state_until_state_change(
                raiden=raiden,
                payment_network_identifier=raiden.default_registry.address,
                token_address=token_address,
                channel_identifier=canonical_identifier.channel_identifier,
                state_change_identifier=state_change_identifier,
            )

            gain = get_batch_unlock_gain(
                restored_channel_state,
            )

            skip_unlock = (
                restored_channel_state.our_state.address == participant and
                gain.from_our_locks == 0
            )
            if not skip_unlock:
                unlock(
                    raiden=raiden,
                    payment_channel=payment_channel,
                    end_state=restored_channel_state.our_state,
                    participant=partner_address,
                    partner=our_address,
                )

    @staticmethod
    def handle_contract_send_channelsettle(
            raiden: 'RaidenService',
            channel_settle_event: ContractSendChannelSettle,
    ):
        canonical_identifier = CanonicalIdentifier(
            chain_identifier=raiden.chain.network_id,
            token_network_address=channel_settle_event.token_network_identifier,
            channel_identifier=channel_settle_event.channel_identifier,
        )
        triggered_by_block_hash = channel_settle_event.triggered_by_block_hash

        payment_channel: PaymentChannel = raiden.chain.payment_channel(
            canonical_identifier=canonical_identifier,
        )
        token_network_proxy: TokenNetwork = payment_channel.token_network

        if not token_network_proxy.client.can_query_state_for_block(triggered_by_block_hash):
            # The only time this can happen is during restarts after a long time
            # when the triggered block ends up getting pruned
            # In that case it's safe to just use the latest view of the chain to
            # query the on-chain participant/channel details
            triggered_by_block_hash = token_network_proxy.client.blockhash_from_blocknumber(
                'latest',
            )

        participants_details = token_network_proxy.detail_participants(
            participant1=payment_channel.participant1,
            participant2=payment_channel.participant2,
            block_identifier=triggered_by_block_hash,
            channel_identifier=channel_settle_event.channel_identifier,
        )

        our_details = participants_details.our_details
        partner_details = participants_details.partner_details

        log_details = {
            'chain_id': canonical_identifier.chain_identifier,
            'token_network_identifier': canonical_identifier.token_network_address,
            'channel_identifier': canonical_identifier.channel_identifier,
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
                canonical_identifier=canonical_identifier,
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
                canonical_identifier=canonical_identifier,
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
