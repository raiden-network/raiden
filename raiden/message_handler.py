from typing import TYPE_CHECKING

import structlog
from eth_utils import to_hex

from raiden.constants import ABSENT_SECRET
from raiden.messages.abstract import Message
from raiden.messages.decode import balanceproof_from_envelope, lockedtransfersigned_from_message
from raiden.messages.synchronization import Delivered, Processed
from raiden.messages.transfers import (
    LockedTransfer,
    LockExpired,
    RefundTransfer,
    RevealSecret,
    SecretRequest,
    Unlock,
)
from raiden.messages.withdraw import WithdrawConfirmation, WithdrawExpired, WithdrawRequest
from raiden.transfer import views
from raiden.transfer.architecture import StateChange
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.state_change import (
    ActionTransferReroute,
    ReceiveLockExpired,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferCancelRoute,
    ReceiveTransferRefund,
)
from raiden.transfer.state_change import (
    ReceiveDelivered,
    ReceiveProcessed,
    ReceiveUnlock,
    ReceiveWithdrawConfirmation,
    ReceiveWithdrawExpired,
    ReceiveWithdrawRequest,
)
from raiden.utils import random_secret
from raiden.utils.typing import MYPY_ANNOTATION, List

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService

log = structlog.get_logger(__name__)


class MessageHandler:
    def on_message(self, raiden: "RaidenService", message: Message) -> None:
        # pylint: disable=unidiomatic-typecheck

        if type(message) == SecretRequest:
            assert isinstance(message, SecretRequest), MYPY_ANNOTATION
            self.handle_message_secretrequest(raiden, message)

        elif type(message) == RevealSecret:
            assert isinstance(message, RevealSecret), MYPY_ANNOTATION
            self.handle_message_revealsecret(raiden, message)

        elif type(message) == Unlock:
            assert isinstance(message, Unlock), MYPY_ANNOTATION
            self.handle_message_unlock(raiden, message)

        elif type(message) == LockExpired:
            assert isinstance(message, LockExpired), MYPY_ANNOTATION
            self.handle_message_lockexpired(raiden, message)

        elif type(message) == RefundTransfer:
            assert isinstance(message, RefundTransfer), MYPY_ANNOTATION
            self.handle_message_refundtransfer(raiden, message)

        elif type(message) == LockedTransfer:
            assert isinstance(message, LockedTransfer), MYPY_ANNOTATION
            self.handle_message_lockedtransfer(raiden, message)

        elif type(message) == WithdrawRequest:
            assert isinstance(message, WithdrawRequest), MYPY_ANNOTATION
            self.handle_message_withdrawrequest(raiden, message)

        elif type(message) == WithdrawConfirmation:
            assert isinstance(message, WithdrawConfirmation), MYPY_ANNOTATION
            self.handle_message_withdraw_confirmation(raiden, message)

        elif type(message) == WithdrawExpired:
            assert isinstance(message, WithdrawExpired), MYPY_ANNOTATION
            self.handle_message_withdraw_expired(raiden, message)

        elif type(message) == Delivered:
            assert isinstance(message, Delivered), MYPY_ANNOTATION
            self.handle_message_delivered(raiden, message)

        elif type(message) == Processed:
            assert isinstance(message, Processed), MYPY_ANNOTATION
            self.handle_message_processed(raiden, message)
        else:
            log.error(f"Unknown message cmdid {message.cmdid}")

    @staticmethod
    def handle_message_withdrawrequest(raiden: "RaidenService", message: WithdrawRequest) -> None:
        assert message.sender, "message must be signed"
        withdraw_request = ReceiveWithdrawRequest(
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=message.chain_id,
                token_network_address=message.token_network_address,
                channel_identifier=message.channel_identifier,
            ),
            message_identifier=message.message_identifier,
            total_withdraw=message.total_withdraw,
            sender=message.sender,
            participant=message.participant,
            nonce=message.nonce,
            expiration=message.expiration,
            signature=message.signature,
        )
        raiden.handle_and_track_state_changes([withdraw_request])

    @staticmethod
    def handle_message_withdraw_confirmation(
        raiden: "RaidenService", message: WithdrawConfirmation
    ) -> None:
        assert message.sender, "message must be signed"
        withdraw = ReceiveWithdrawConfirmation(
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=message.chain_id,
                token_network_address=message.token_network_address,
                channel_identifier=message.channel_identifier,
            ),
            message_identifier=message.message_identifier,
            total_withdraw=message.total_withdraw,
            sender=message.sender,
            participant=message.participant,
            nonce=message.nonce,
            expiration=message.expiration,
            signature=message.signature,
        )
        raiden.handle_and_track_state_changes([withdraw])

    @staticmethod
    def handle_message_withdraw_expired(raiden: "RaidenService", message: WithdrawExpired) -> None:
        assert message.sender, "message must be signed"
        withdraw_expired = ReceiveWithdrawExpired(
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=message.chain_id,
                token_network_address=message.token_network_address,
                channel_identifier=message.channel_identifier,
            ),
            message_identifier=message.message_identifier,
            total_withdraw=message.total_withdraw,
            sender=message.sender,
            participant=message.participant,
            nonce=message.nonce,
            expiration=message.expiration,
            signature=message.signature,
        )
        raiden.handle_and_track_state_changes([withdraw_expired])

    @staticmethod
    def handle_message_secretrequest(raiden: "RaidenService", message: SecretRequest) -> None:
        assert message.sender, "message must be signed"
        secret_request = ReceiveSecretRequest(
            payment_identifier=message.payment_identifier,
            amount=message.amount,
            expiration=message.expiration,
            secrethash=message.secrethash,
            sender=message.sender,
        )
        raiden.handle_and_track_state_changes([secret_request])

    @staticmethod
    def handle_message_revealsecret(raiden: "RaidenService", message: RevealSecret) -> None:
        assert message.sender, "message must be signed"
        state_change = ReceiveSecretReveal(secret=message.secret, sender=message.sender)
        raiden.handle_and_track_state_changes([state_change])

    @staticmethod
    def handle_message_unlock(raiden: "RaidenService", message: Unlock) -> None:
        balance_proof = balanceproof_from_envelope(message)
        state_change = ReceiveUnlock(
            message_identifier=message.message_identifier,
            secret=message.secret,
            balance_proof=balance_proof,
            sender=balance_proof.sender,
        )
        raiden.handle_and_track_state_changes([state_change])

    @staticmethod
    def handle_message_lockexpired(raiden: "RaidenService", message: LockExpired) -> None:
        balance_proof = balanceproof_from_envelope(message)
        state_change = ReceiveLockExpired(
            sender=balance_proof.sender,
            balance_proof=balance_proof,
            secrethash=message.secrethash,
            message_identifier=message.message_identifier,
        )
        raiden.handle_and_track_state_changes([state_change])

    @staticmethod
    def handle_message_refundtransfer(raiden: "RaidenService", message: RefundTransfer) -> None:
        chain_state = views.state_from_raiden(raiden)
        from_transfer = lockedtransfersigned_from_message(message=message)

        role = views.get_transfer_role(
            chain_state=chain_state, secrethash=from_transfer.lock.secrethash
        )

        state_changes: List[StateChange] = []

        if role == "initiator":
            old_secret = views.get_transfer_secret(chain_state, from_transfer.lock.secrethash)
            is_secret_known = old_secret is not None and old_secret != ABSENT_SECRET

            state_changes.append(
                ReceiveTransferCancelRoute(
                    transfer=from_transfer,
                    balance_proof=from_transfer.balance_proof,
                    sender=from_transfer.balance_proof.sender,  # pylint: disable=no-member
                )
            )

            # Currently, the only case where we can be initiators and not
            # know the secret is if the transfer is part of an atomic swap. In
            # the case of an atomic swap, we will not try to re-route the
            # transfer. In all other cases we can try to find another route
            # (and generate a new secret)
            if is_secret_known:
                state_changes.append(
                    ActionTransferReroute(
                        transfer=from_transfer,
                        balance_proof=from_transfer.balance_proof,  # pylint: disable=no-member
                        sender=from_transfer.balance_proof.sender,  # pylint: disable=no-member
                        secret=random_secret(),
                    )
                )
        else:
            state_changes.append(
                ReceiveTransferRefund(
                    transfer=from_transfer,
                    balance_proof=from_transfer.balance_proof,
                    sender=from_transfer.balance_proof.sender,  # pylint: disable=no-member
                )
            )

        raiden.handle_and_track_state_changes(state_changes)

    @staticmethod
    def handle_message_lockedtransfer(raiden: "RaidenService", message: LockedTransfer) -> None:
        secrethash = message.lock.secrethash
        # We must check if the secret was registered against the latest block,
        # even if the block is forked away and the transaction that registers
        # the secret is removed from the blockchain. The rationale here is that
        # someone else does know the secret, regardless of the chain state, so
        # the node must not use it to start a payment.
        #
        # For this particular case, it's preferable to use `latest` instead of
        # having a specific block_hash, because it's preferable to know if the secret
        # was ever known, rather than having a consistent view of the blockchain.
        registered = raiden.default_secret_registry.is_secret_registered(
            secrethash=secrethash, block_identifier="latest"
        )
        if registered:
            log.warning(
                f"Ignoring received locked transfer with secrethash {to_hex(secrethash)} "
                f"since it is already registered in the secret registry"
            )
            return

        if message.target == raiden.address:
            raiden.target_mediated_transfer(message)
        else:
            raiden.mediate_mediated_transfer(message)

    @staticmethod
    def handle_message_processed(raiden: "RaidenService", message: Processed) -> None:
        assert message.sender, "message must be signed"
        processed = ReceiveProcessed(message.sender, message.message_identifier)
        raiden.handle_and_track_state_changes([processed])

    @staticmethod
    def handle_message_delivered(raiden: "RaidenService", message: Delivered) -> None:
        assert message.sender, "message must be signed"
        delivered = ReceiveDelivered(message.sender, message.delivered_message_identifier)
        raiden.handle_and_track_state_changes([delivered])
