from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import structlog
from eth_utils import encode_hex, to_checksum_address, to_hex

from raiden.constants import (
    EMPTY_BALANCE_HASH,
    EMPTY_HASH,
    EMPTY_MESSAGE_HASH,
    EMPTY_SIGNATURE,
    LOCKSROOT_OF_NO_LOCKS,
)
from raiden.exceptions import InsufficientEth, RaidenUnrecoverableError
from raiden.messages.encode import message_from_sendevent
from raiden.network.pathfinding import post_pfs_feedback
from raiden.network.proxies.payment_channel import PaymentChannel
from raiden.network.proxies.token_network import TokenNetwork
from raiden.network.resolver.client import reveal_secret_with_resolver
from raiden.services import send_pfs_update
from raiden.storage.restore import (
    channel_state_until_state_change,
    get_event_with_balance_proof_by_balance_hash,
    get_event_with_balance_proof_by_locksroot,
    get_state_change_with_balance_proof_by_balance_hash,
    get_state_change_with_balance_proof_by_locksroot,
)
from raiden.transfer.architecture import Event
from raiden.transfer.channel import get_batch_unlock, get_batch_unlock_gain
from raiden.transfer.events import (
    ContractSendChannelBatchUnlock,
    ContractSendChannelClose,
    ContractSendChannelSettle,
    ContractSendChannelUpdateTransfer,
    ContractSendChannelWithdraw,
    ContractSendSecretReveal,
    EventInvalidActionSetRevealTimeout,
    EventInvalidActionWithdraw,
    EventInvalidReceivedLockedTransfer,
    EventInvalidReceivedLockExpired,
    EventInvalidReceivedTransferRefund,
    EventInvalidReceivedUnlock,
    EventInvalidReceivedWithdraw,
    EventInvalidReceivedWithdrawExpired,
    EventInvalidReceivedWithdrawRequest,
    EventInvalidSecretRequest,
    EventPaymentReceivedSuccess,
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
    SendPFSFeeUpdate,
    SendProcessed,
    SendWithdrawConfirmation,
    SendWithdrawExpired,
    SendWithdrawRequest,
)
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.events import (
    EventRouteFailed,
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
from raiden.transfer.state import ChainState, NettingChannelEndState
from raiden.transfer.views import get_channelstate_by_token_network_and_partner
from raiden.utils.packing import pack_signed_balance_proof, pack_withdraw
from raiden.utils.typing import MYPY_ANNOTATION, Address, BlockSpecification, Nonce
from raiden_contracts.constants import MessageTypeId

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.raiden_service import RaidenService

log = structlog.get_logger(__name__)
UNEVENTFUL_EVENTS = (
    EventPaymentReceivedSuccess,
    EventUnlockSuccess,
    EventUnlockClaimFailed,
    EventUnlockClaimSuccess,
    EventInvalidActionWithdraw,
    EventInvalidActionSetRevealTimeout,
    EventInvalidReceivedLockedTransfer,
    EventInvalidReceivedLockExpired,
    EventInvalidReceivedTransferRefund,
    EventInvalidReceivedUnlock,
    EventInvalidReceivedWithdrawExpired,
    EventInvalidReceivedWithdrawRequest,
    EventInvalidReceivedWithdraw,
    EventRouteFailed,
)


def unlock(
    payment_channel: PaymentChannel,
    end_state: NettingChannelEndState,
    sender: Address,
    receiver: Address,
    given_block_identifier: BlockSpecification,
) -> None:  # pragma: no unittest
    pending_locks = get_batch_unlock(end_state)
    assert pending_locks, "pending lock set is missing"

    payment_channel.unlock(
        sender=sender,
        receiver=receiver,
        pending_locks=pending_locks,
        given_block_identifier=given_block_identifier,
    )


class EventHandler(ABC):
    @abstractmethod
    def on_raiden_event(
        self, raiden: "RaidenService", chain_state: ChainState, event: Event
    ) -> None:
        pass


class RaidenEventHandler(EventHandler):
    def on_raiden_event(
        self, raiden: "RaidenService", chain_state: ChainState, event: Event
    ) -> None:  # pragma: no unittest
        # pylint: disable=too-many-branches
        if type(event) == SendLockExpired:
            assert isinstance(event, SendLockExpired), MYPY_ANNOTATION
            self.handle_send_lockexpired(raiden, event)
        elif type(event) == SendLockedTransfer:
            assert isinstance(event, SendLockedTransfer), MYPY_ANNOTATION
            self.handle_send_lockedtransfer(raiden, event)
        elif type(event) == SendSecretReveal:
            assert isinstance(event, SendSecretReveal), MYPY_ANNOTATION
            self.handle_send_secretreveal(raiden, event)
        elif type(event) == SendBalanceProof:
            assert isinstance(event, SendBalanceProof), MYPY_ANNOTATION
            self.handle_send_balanceproof(raiden, event)
        elif type(event) == SendSecretRequest:
            assert isinstance(event, SendSecretRequest), MYPY_ANNOTATION
            self.handle_send_secretrequest(raiden, chain_state, event)
        elif type(event) == SendRefundTransfer:
            assert isinstance(event, SendRefundTransfer), MYPY_ANNOTATION
            self.handle_send_refundtransfer(raiden, event)
        elif type(event) == SendWithdrawRequest:
            assert isinstance(event, SendWithdrawRequest), MYPY_ANNOTATION
            self.handle_send_withdrawrequest(raiden, event)
        elif type(event) == SendWithdrawConfirmation:
            assert isinstance(event, SendWithdrawConfirmation), MYPY_ANNOTATION
            self.handle_send_withdraw(raiden, event)
        elif type(event) == SendWithdrawExpired:
            assert isinstance(event, SendWithdrawExpired), MYPY_ANNOTATION
            self.handle_send_withdrawexpired(raiden, event)
        elif type(event) == SendProcessed:
            assert isinstance(event, SendProcessed), MYPY_ANNOTATION
            self.handle_send_processed(raiden, event)
        elif type(event) == EventPaymentSentSuccess:
            assert isinstance(event, EventPaymentSentSuccess), MYPY_ANNOTATION
            self.handle_paymentsentsuccess(raiden, event)
        elif type(event) == EventPaymentSentFailed:
            assert isinstance(event, EventPaymentSentFailed), MYPY_ANNOTATION
            self.handle_paymentsentfailed(raiden, event)
        elif type(event) == EventUnlockFailed:
            assert isinstance(event, EventUnlockFailed), MYPY_ANNOTATION
            self.handle_unlockfailed(raiden, event)
        elif type(event) == EventInvalidSecretRequest:
            assert isinstance(event, EventInvalidSecretRequest), MYPY_ANNOTATION
            self.handle_invalidsecretrequest(raiden, event)
        elif type(event) == ContractSendSecretReveal:
            assert isinstance(event, ContractSendSecretReveal), MYPY_ANNOTATION
            self.handle_contract_send_secretreveal(raiden, event)
        elif type(event) == ContractSendChannelClose:
            assert isinstance(event, ContractSendChannelClose), MYPY_ANNOTATION
            self.handle_contract_send_channelclose(raiden, chain_state, event)
        elif type(event) == ContractSendChannelUpdateTransfer:
            assert isinstance(event, ContractSendChannelUpdateTransfer), MYPY_ANNOTATION
            self.handle_contract_send_channelupdate(raiden, event)
        elif type(event) == ContractSendChannelBatchUnlock:
            assert isinstance(event, ContractSendChannelBatchUnlock), MYPY_ANNOTATION
            self.handle_contract_send_channelunlock(raiden, chain_state, event)
        elif type(event) == ContractSendChannelSettle:
            assert isinstance(event, ContractSendChannelSettle), MYPY_ANNOTATION
            self.handle_contract_send_channelsettle(raiden, event)
        elif type(event) == ContractSendChannelWithdraw:
            assert isinstance(event, ContractSendChannelWithdraw), MYPY_ANNOTATION
            self.handle_contract_send_channelwithdraw(raiden, event)
        elif type(event) == SendPFSFeeUpdate:
            assert isinstance(event, SendPFSFeeUpdate), MYPY_ANNOTATION
            self.handle_send_pfs_fee_update(raiden, event)
        elif type(event) in UNEVENTFUL_EVENTS:
            pass
        else:
            log.error(
                "Unknown event",
                event_type=str(type(event)),
                node=to_checksum_address(raiden.address),
            )

    @staticmethod
    def handle_send_pfs_fee_update(
        raiden: "RaidenService", event: SendPFSFeeUpdate
    ) -> None:  # pragma: no unittest
        send_pfs_update(
            raiden=raiden,
            canonical_identifier=event.canonical_identifier,
            update_fee_schedule=True,
        )

    @staticmethod
    def handle_send_lockexpired(
        raiden: "RaidenService", send_lock_expired: SendLockExpired
    ) -> None:  # pragma: no unittest
        lock_expired_message = message_from_sendevent(send_lock_expired)
        raiden.sign(lock_expired_message)
        raiden.transport.send_async(send_lock_expired.queue_identifier, lock_expired_message)

    @staticmethod
    def handle_send_lockedtransfer(
        raiden: "RaidenService", send_locked_transfer: SendLockedTransfer
    ) -> None:  # pragma: no unittest
        mediated_transfer_message = message_from_sendevent(send_locked_transfer)
        raiden.sign(mediated_transfer_message)
        raiden.transport.send_async(
            send_locked_transfer.queue_identifier, mediated_transfer_message
        )

    @staticmethod
    def handle_send_secretreveal(
        raiden: "RaidenService", reveal_secret_event: SendSecretReveal
    ) -> None:  # pragma: no unittest
        reveal_secret_message = message_from_sendevent(reveal_secret_event)
        raiden.sign(reveal_secret_message)
        raiden.transport.send_async(reveal_secret_event.queue_identifier, reveal_secret_message)

    @staticmethod
    def handle_send_balanceproof(
        raiden: "RaidenService", balance_proof_event: SendBalanceProof
    ) -> None:  # pragma: no unittest
        unlock_message = message_from_sendevent(balance_proof_event)
        raiden.sign(unlock_message)
        raiden.transport.send_async(balance_proof_event.queue_identifier, unlock_message)

    @staticmethod
    def handle_send_secretrequest(
        raiden: "RaidenService", chain_state: ChainState, secret_request_event: SendSecretRequest
    ) -> None:  # pragma: no unittest
        if reveal_secret_with_resolver(raiden, chain_state, secret_request_event):
            return

        secret_request_message = message_from_sendevent(secret_request_event)
        raiden.sign(secret_request_message)
        raiden.transport.send_async(secret_request_event.queue_identifier, secret_request_message)

    @staticmethod
    def handle_send_refundtransfer(
        raiden: "RaidenService", refund_transfer_event: SendRefundTransfer
    ) -> None:  # pragma: no unittest
        refund_transfer_message = message_from_sendevent(refund_transfer_event)
        raiden.sign(refund_transfer_message)
        raiden.transport.send_async(
            refund_transfer_event.queue_identifier, refund_transfer_message
        )

    @staticmethod
    def handle_send_withdrawrequest(
        raiden: "RaidenService", withdraw_request_event: SendWithdrawRequest
    ) -> None:
        withdraw_request_message = message_from_sendevent(withdraw_request_event)
        raiden.sign(withdraw_request_message)
        raiden.transport.send_async(
            withdraw_request_event.queue_identifier, withdraw_request_message
        )

    @staticmethod
    def handle_send_withdraw(
        raiden: "RaidenService", withdraw_event: SendWithdrawConfirmation
    ) -> None:
        withdraw_message = message_from_sendevent(withdraw_event)
        raiden.sign(withdraw_message)
        raiden.transport.send_async(withdraw_event.queue_identifier, withdraw_message)

    @staticmethod
    def handle_send_withdrawexpired(
        raiden: "RaidenService", withdraw_expired_event: SendWithdrawExpired
    ) -> None:
        withdraw_expired_message = message_from_sendevent(withdraw_expired_event)
        raiden.sign(withdraw_expired_message)
        raiden.transport.send_async(
            withdraw_expired_event.queue_identifier, withdraw_expired_message
        )

    @staticmethod
    def handle_send_processed(
        raiden: "RaidenService", processed_event: SendProcessed
    ) -> None:  # pragma: no unittest
        processed_message = message_from_sendevent(processed_event)
        raiden.sign(processed_message)
        raiden.transport.send_async(processed_event.queue_identifier, processed_message)

    @staticmethod
    def handle_paymentsentsuccess(
        raiden: "RaidenService", payment_sent_success_event: EventPaymentSentSuccess
    ) -> None:  # pragma: no unittest
        target = payment_sent_success_event.target
        payment_identifier = payment_sent_success_event.identifier
        payment_status = raiden.targets_to_identifiers_to_statuses[target].pop(payment_identifier)

        # With the introduction of the lock we should always get
        # here only once per identifier so payment_status should always exist
        # see: https://github.com/raiden-network/raiden/pull/3191
        payment_status.payment_done.set(payment_sent_success_event)

    @staticmethod
    def handle_paymentsentfailed(
        raiden: "RaidenService", payment_sent_failed_event: EventPaymentSentFailed
    ) -> None:  # pragma: no unittest
        target = payment_sent_failed_event.target
        payment_identifier = payment_sent_failed_event.identifier
        payment_status = raiden.targets_to_identifiers_to_statuses[target].pop(
            payment_identifier, None
        )
        # In the case of a refund transfer the payment fails earlier
        # but the lock expiration will generate a second
        # EventPaymentSentFailed message which we can ignore here
        if payment_status:
            payment_status.payment_done.set(payment_sent_failed_event)

    @staticmethod
    def handle_unlockfailed(
        raiden: "RaidenService", unlock_failed_event: EventUnlockFailed
    ) -> None:  # pragma: no unittest
        # pylint: disable=unused-argument
        log.error(
            "UnlockFailed!",
            secrethash=to_hex(unlock_failed_event.secrethash),
            reason=unlock_failed_event.reason,
            node=to_checksum_address(raiden.address),
        )

    @staticmethod
    def handle_invalidsecretrequest(
        raiden: "RaidenService", invalid_secret_request_event: EventInvalidSecretRequest
    ) -> None:  # pragma: no unittest
        # pylint: disable=unused-argument
        log.warning(
            "Received invalid SecretRequest!",
            payment_id=invalid_secret_request_event.payment_identifier,
            intended_amount=invalid_secret_request_event.intended_amount,
            actual_amount=invalid_secret_request_event.actual_amount,
            node=to_checksum_address(raiden.address),
        )

    @staticmethod
    def handle_contract_send_secretreveal(
        raiden: "RaidenService", channel_reveal_secret_event: ContractSendSecretReveal
    ) -> None:  # pragma: no unittest
        try:
            raiden.default_secret_registry.register_secret(
                secret=channel_reveal_secret_event.secret
            )
        except InsufficientEth as e:
            raise RaidenUnrecoverableError(str(e)) from e

    @staticmethod
    def handle_contract_send_channelwithdraw(
        raiden: "RaidenService", channel_withdraw_event: ContractSendChannelWithdraw
    ) -> None:
        withdraw_confirmation_data = pack_withdraw(
            canonical_identifier=channel_withdraw_event.canonical_identifier,
            participant=raiden.address,
            total_withdraw=channel_withdraw_event.total_withdraw,
            expiration_block=channel_withdraw_event.expiration,
        )
        our_signature = raiden.signer.sign(data=withdraw_confirmation_data)

        channel_proxy = raiden.proxy_manager.payment_channel(
            canonical_identifier=channel_withdraw_event.canonical_identifier
        )

        try:
            channel_proxy.set_total_withdraw(
                total_withdraw=channel_withdraw_event.total_withdraw,
                expiration_block=channel_withdraw_event.expiration,
                participant_signature=our_signature,
                partner_signature=channel_withdraw_event.partner_signature,
                block_identifier=channel_withdraw_event.triggered_by_block_hash,
            )
        except InsufficientEth as e:
            raise RaidenUnrecoverableError(str(e)) from e

    @staticmethod
    def handle_contract_send_channelclose(
        raiden: "RaidenService",
        chain_state: ChainState,
        channel_close_event: ContractSendChannelClose,
    ) -> None:
        balance_proof = channel_close_event.balance_proof

        if balance_proof:
            nonce = balance_proof.nonce
            balance_hash = balance_proof.balance_hash
            signature_in_proof = balance_proof.signature
            message_hash = balance_proof.message_hash
            canonical_identifier = balance_proof.canonical_identifier

        else:
            nonce = Nonce(0)
            balance_hash = EMPTY_BALANCE_HASH
            signature_in_proof = EMPTY_SIGNATURE
            message_hash = EMPTY_MESSAGE_HASH
            canonical_identifier = channel_close_event.canonical_identifier

        closing_data = pack_signed_balance_proof(
            msg_type=MessageTypeId.BALANCE_PROOF,
            nonce=nonce,
            balance_hash=balance_hash,
            additional_hash=message_hash,
            canonical_identifier=canonical_identifier,
            partner_signature=signature_in_proof,
        )

        our_signature = raiden.signer.sign(data=closing_data)

        channel_proxy = raiden.proxy_manager.payment_channel(
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=chain_state.chain_id,
                token_network_address=channel_close_event.token_network_address,
                channel_identifier=channel_close_event.channel_identifier,
            )
        )

        channel_proxy.close(
            nonce=nonce,
            balance_hash=balance_hash,
            additional_hash=message_hash,
            non_closing_signature=signature_in_proof,
            closing_signature=our_signature,
            block_identifier=channel_close_event.triggered_by_block_hash,
        )

    @staticmethod
    def handle_contract_send_channelupdate(
        raiden: "RaidenService", channel_update_event: ContractSendChannelUpdateTransfer
    ) -> None:
        balance_proof = channel_update_event.balance_proof

        if balance_proof:
            canonical_identifier = balance_proof.canonical_identifier
            channel = raiden.proxy_manager.payment_channel(
                canonical_identifier=canonical_identifier
            )

            non_closing_data = pack_signed_balance_proof(
                msg_type=MessageTypeId.BALANCE_PROOF_UPDATE,
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
            except InsufficientEth as e:
                raise RaidenUnrecoverableError(
                    f"{str(e)}\n"
                    "CAUTION: This happened when updating our side of the channel "
                    "during a channel settlement. You are in immediate danger of "
                    "losing funds in this channel."
                ) from e

    @staticmethod
    def handle_contract_send_channelunlock(
        raiden: "RaidenService",
        chain_state: ChainState,
        channel_unlock_event: ContractSendChannelBatchUnlock,
    ) -> None:
        assert raiden.wal, "The Raiden Service must be initialize to handle events"

        canonical_identifier = channel_unlock_event.canonical_identifier
        token_network_address = canonical_identifier.token_network_address
        channel_identifier = canonical_identifier.channel_identifier
        participant = channel_unlock_event.sender

        payment_channel: PaymentChannel = raiden.proxy_manager.payment_channel(
            canonical_identifier=canonical_identifier
        )

        channel_state = get_channelstate_by_token_network_and_partner(
            chain_state=chain_state,
            token_network_address=token_network_address,
            partner_address=participant,
        )

        if not channel_state:
            # channel was cleaned up already due to an unlock
            raise RaidenUnrecoverableError(
                f"Failed to find channel state with partner:"
                f"{to_checksum_address(participant)}, "
                f"token_network:{to_checksum_address(token_network_address)}"
            )

        our_address = channel_state.our_state.address
        our_locksroot = channel_state.our_state.onchain_locksroot

        partner_address = channel_state.partner_state.address
        partner_locksroot = channel_state.partner_state.onchain_locksroot

        # we want to unlock because there are on-chain unlocked locks
        search_events = our_locksroot != LOCKSROOT_OF_NO_LOCKS
        # we want to unlock, because there are unlocked/unclaimed locks
        search_state_changes = partner_locksroot != LOCKSROOT_OF_NO_LOCKS

        if not search_events and not search_state_changes:
            # In the case that someone else sent the unlock we do nothing
            # Check https://github.com/raiden-network/raiden/issues/3152
            # for more details
            log.warning(
                "Onchain unlock already mined",
                canonical_identifier=canonical_identifier,
                channel_identifier=canonical_identifier.channel_identifier,
                participant=to_checksum_address(participant),
            )
            return

        if search_state_changes:
            state_change_record = get_state_change_with_balance_proof_by_locksroot(
                storage=raiden.wal.storage,
                canonical_identifier=canonical_identifier,
                locksroot=partner_locksroot,
                sender=partner_address,
            )

            if state_change_record is None:
                raise RaidenUnrecoverableError(
                    f"Failed to find state that matches the current channel locksroots. "
                    f"chain_id:{raiden.rpc_client.chain_id} "
                    f"token_network:{to_checksum_address(token_network_address)} "
                    f"channel:{channel_identifier} "
                    f"participant:{to_checksum_address(participant)} "
                    f"our_locksroot:{to_hex(our_locksroot)} "
                    f"partner_locksroot:{to_hex(partner_locksroot)} "
                )

            state_change_identifier = state_change_record.state_change_identifier
            restored_channel_state = channel_state_until_state_change(
                raiden=raiden,
                canonical_identifier=canonical_identifier,
                state_change_identifier=state_change_identifier,
            )
            assert restored_channel_state is not None

            gain = get_batch_unlock_gain(restored_channel_state)

            skip_unlock = (
                restored_channel_state.partner_state.address == participant
                and gain.from_partner_locks == 0
            )
            if not skip_unlock:
                unlock(
                    payment_channel=payment_channel,
                    end_state=restored_channel_state.partner_state,
                    sender=partner_address,
                    receiver=our_address,
                    given_block_identifier=channel_unlock_event.triggered_by_block_hash,
                )

        if search_events:
            event_record = get_event_with_balance_proof_by_locksroot(
                storage=raiden.wal.storage,
                canonical_identifier=canonical_identifier,
                locksroot=our_locksroot,
                recipient=partner_address,
            )

            if event_record is None:
                raise RaidenUnrecoverableError(
                    f"Failed to find event that match current channel locksroots. "
                    f"chain_id:{raiden.rpc_client.chain_id} "
                    f"token_network:{to_checksum_address(token_network_address)} "
                    f"channel:{channel_identifier} "
                    f"participant:{to_checksum_address(participant)} "
                    f"our_locksroot:{to_hex(our_locksroot)} "
                    f"partner_locksroot:{to_hex(partner_locksroot)} "
                )

            state_change_identifier = event_record.state_change_identifier
            restored_channel_state = channel_state_until_state_change(
                raiden=raiden,
                canonical_identifier=canonical_identifier,
                state_change_identifier=state_change_identifier,
            )
            assert restored_channel_state is not None

            gain = get_batch_unlock_gain(restored_channel_state)

            skip_unlock = (
                restored_channel_state.our_state.address == participant
                and gain.from_our_locks == 0
            )
            if not skip_unlock:
                try:
                    unlock(
                        payment_channel=payment_channel,
                        end_state=restored_channel_state.our_state,
                        sender=our_address,
                        receiver=partner_address,
                        given_block_identifier=channel_unlock_event.triggered_by_block_hash,
                    )
                except InsufficientEth as e:
                    raise RaidenUnrecoverableError(str(e)) from e

    @staticmethod
    def handle_contract_send_channelsettle(
        raiden: "RaidenService", channel_settle_event: ContractSendChannelSettle
    ) -> None:
        assert raiden.wal, "The Raiden Service must be initialize to handle events"

        canonical_identifier = CanonicalIdentifier(
            chain_identifier=raiden.rpc_client.chain_id,
            token_network_address=channel_settle_event.token_network_address,
            channel_identifier=channel_settle_event.channel_identifier,
        )
        triggered_by_block_hash = channel_settle_event.triggered_by_block_hash

        payment_channel: PaymentChannel = raiden.proxy_manager.payment_channel(
            canonical_identifier=canonical_identifier
        )
        token_network_proxy: TokenNetwork = payment_channel.token_network

        try:
            participants_details = token_network_proxy.detail_participants(
                participant1=payment_channel.participant1,
                participant2=payment_channel.participant2,
                block_identifier=triggered_by_block_hash,
                channel_identifier=channel_settle_event.channel_identifier,
            )
        except ValueError:
            # The triggered_by_block_hash block was pruned.
            participants_details = token_network_proxy.detail_participants(
                participant1=payment_channel.participant1,
                participant2=payment_channel.participant2,
                block_identifier="latest",
                channel_identifier=channel_settle_event.channel_identifier,
            )

        our_details = participants_details.our_details
        partner_details = participants_details.partner_details

        log_details = {
            "chain_id": canonical_identifier.chain_identifier,
            "token_network_address": canonical_identifier.token_network_address,
            "channel_identifier": canonical_identifier.channel_identifier,
            "node": to_checksum_address(raiden.address),
            "partner": to_checksum_address(partner_details.address),
            "our_deposit": our_details.deposit,
            "our_withdrawn": our_details.withdrawn,
            "our_is_closer": our_details.is_closer,
            "our_balance_hash": to_hex(our_details.balance_hash),
            "our_nonce": our_details.nonce,
            "our_locksroot": to_hex(our_details.locksroot),
            "our_locked_amount": our_details.locked_amount,
            "partner_deposit": partner_details.deposit,
            "partner_withdrawn": partner_details.withdrawn,
            "partner_is_closer": partner_details.is_closer,
            "partner_balance_hash": to_hex(partner_details.balance_hash),
            "partner_nonce": partner_details.nonce,
            "partner_locksroot": to_hex(partner_details.locksroot),
            "partner_locked_amount": partner_details.locked_amount,
        }

        if our_details.balance_hash != EMPTY_HASH:
            event_record = get_event_with_balance_proof_by_balance_hash(
                storage=raiden.wal.storage,
                canonical_identifier=canonical_identifier,
                balance_hash=our_details.balance_hash,
                recipient=participants_details.partner_details.address,
            )

            if event_record is None:
                log.critical("our balance proof not found", **log_details)
                raise RaidenUnrecoverableError(
                    "Our balance proof could not be found in the database"
                )

            our_balance_proof = event_record.data.balance_proof  # type: ignore
            our_transferred_amount = our_balance_proof.transferred_amount
            our_locked_amount = our_balance_proof.locked_amount
            our_locksroot = our_balance_proof.locksroot
        else:
            our_transferred_amount = 0
            our_locked_amount = 0
            our_locksroot = LOCKSROOT_OF_NO_LOCKS

        if partner_details.balance_hash != EMPTY_HASH:
            state_change_record = get_state_change_with_balance_proof_by_balance_hash(
                storage=raiden.wal.storage,
                canonical_identifier=canonical_identifier,
                balance_hash=partner_details.balance_hash,
                sender=participants_details.partner_details.address,
            )
            if state_change_record is None:
                log.critical("partner balance proof not found", **log_details)
                raise RaidenUnrecoverableError(
                    "Partner balance proof could not be found in the database"
                )

            partner_balance_proof = state_change_record.data.balance_proof  # type: ignore
            partner_transferred_amount = partner_balance_proof.transferred_amount
            partner_locked_amount = partner_balance_proof.locked_amount
            partner_locksroot = partner_balance_proof.locksroot
        else:
            partner_transferred_amount = 0
            partner_locked_amount = 0
            partner_locksroot = LOCKSROOT_OF_NO_LOCKS

        try:
            payment_channel.settle(
                transferred_amount=our_transferred_amount,
                locked_amount=our_locked_amount,
                locksroot=our_locksroot,
                partner_transferred_amount=partner_transferred_amount,
                partner_locked_amount=partner_locked_amount,
                partner_locksroot=partner_locksroot,
                block_identifier=triggered_by_block_hash,
            )
        except InsufficientEth as e:
            raise RaidenUnrecoverableError(str(e)) from e


class PFSFeedbackEventHandler(RaidenEventHandler):
    """ A event handler that sends feedback to the PFS. """

    def __init__(self, wrapped_handler: EventHandler) -> None:
        self.wrapped = wrapped_handler

    def on_raiden_event(
        self, raiden: "RaidenService", chain_state: ChainState, event: Event
    ) -> None:  # pragma: no unittest
        if type(event) == EventRouteFailed:
            assert isinstance(event, EventRouteFailed), MYPY_ANNOTATION
            self.handle_routefailed(raiden, event)
        elif type(event) == EventPaymentSentSuccess:
            assert isinstance(event, EventPaymentSentSuccess), MYPY_ANNOTATION
            self.handle_paymentsentsuccess(raiden, event)

        # Call the decorated event handler
        self.wrapped.on_raiden_event(raiden, chain_state, event)

    @staticmethod
    def handle_routefailed(
        raiden: "RaidenService", route_failed_event: EventRouteFailed
    ) -> None:  # pragma: no unittest
        feedback_token = raiden.route_to_feedback_token.get(tuple(route_failed_event.route))
        pfs_config = raiden.config.get("pfs_config")

        if feedback_token and pfs_config:
            log.debug(
                "Received event for failed route",
                route=[to_checksum_address(node) for node in route_failed_event.route],
                secrethash=encode_hex(route_failed_event.secrethash),
                feedback_token=feedback_token,
            )
            post_pfs_feedback(
                routing_mode=raiden.routing_mode,
                pfs_config=pfs_config,
                token_network_address=route_failed_event.token_network_address,
                route=route_failed_event.route,
                token=feedback_token,
                successful=False,
            )

    @staticmethod
    def handle_paymentsentsuccess(
        raiden: "RaidenService", payment_sent_success_event: EventPaymentSentSuccess
    ) -> None:  # pragma: no unittest
        feedback_token = raiden.route_to_feedback_token.get(
            tuple(payment_sent_success_event.route)
        )
        pfs_config = raiden.config.get("pfs_config")

        if feedback_token and pfs_config:
            log.debug(
                "Received payment success event",
                route=[to_checksum_address(node) for node in payment_sent_success_event.route],
                feedback_token=feedback_token,
            )
            post_pfs_feedback(
                routing_mode=raiden.routing_mode,
                pfs_config=pfs_config,
                token_network_address=payment_sent_success_event.token_network_address,
                route=payment_sent_success_event.route,
                token=feedback_token,
                successful=True,
            )
