import structlog
from eth_utils import to_hex
from gevent import joinall
from gevent.pool import Pool

from raiden import routing
from raiden.constants import ABSENT_SECRET, BLOCK_ID_LATEST
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
    ActionInitMediator,
    ActionInitTarget,
    ActionTransferReroute,
    BalanceProofStateChange,
    ReceiveLockExpired,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferCancelRoute,
    ReceiveTransferRefund,
)
from raiden.transfer.state import HopState
from raiden.transfer.state_change import (
    ReceiveDelivered,
    ReceiveProcessed,
    ReceiveUnlock,
    ReceiveWithdrawConfirmation,
    ReceiveWithdrawExpired,
    ReceiveWithdrawRequest,
)
from raiden.utils.transfers import random_secret
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    TYPE_CHECKING,
    Address,
    List,
    Set,
    TargetAddress,
    Tuple,
)

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService

log = structlog.get_logger(__name__)


class MessageHandler:
    def on_messages(self, raiden: "RaidenService", messages: List[Message]) -> None:
        # pylint: disable=unidiomatic-typecheck

        # Remove duplicated messages, this can happen because of retries done
        # by the sender when the receiver takes too long to acknowledge. This
        # is a problem since the receiver may be taking a long time to reply
        # because it is under high load, processing the duplicated messages
        # just make the problem worse.
        unique_messages: Set[Message] = set(messages)

        pool = Pool()

        for message in unique_messages:
            if type(message) == SecretRequest:
                assert isinstance(message, SecretRequest), MYPY_ANNOTATION
                pool.apply_async(self.handle_message_secretrequest, (raiden, message))

            elif type(message) == RevealSecret:
                assert isinstance(message, RevealSecret), MYPY_ANNOTATION
                pool.apply_async(self.handle_message_revealsecret, (raiden, message))

            elif type(message) == Unlock:
                assert isinstance(message, Unlock), MYPY_ANNOTATION
                pool.apply_async(self.handle_message_unlock, (raiden, message))

            elif type(message) == LockExpired:
                assert isinstance(message, LockExpired), MYPY_ANNOTATION
                pool.apply_async(self.handle_message_lockexpired, (raiden, message))

            elif type(message) == RefundTransfer:
                assert isinstance(message, RefundTransfer), MYPY_ANNOTATION
                pool.apply_async(self.handle_message_refundtransfer, (raiden, message))

            elif type(message) == LockedTransfer:
                assert isinstance(message, LockedTransfer), MYPY_ANNOTATION
                pool.apply_async(self.handle_message_lockedtransfer, (raiden, message))

            elif type(message) == WithdrawRequest:
                assert isinstance(message, WithdrawRequest), MYPY_ANNOTATION
                pool.apply_async(self.handle_message_withdrawrequest, (raiden, message))

            elif type(message) == WithdrawConfirmation:
                assert isinstance(message, WithdrawConfirmation), MYPY_ANNOTATION
                pool.apply_async(self.handle_message_withdraw_confirmation, (raiden, message))

            elif type(message) == WithdrawExpired:
                assert isinstance(message, WithdrawExpired), MYPY_ANNOTATION
                pool.apply_async(self.handle_message_withdraw_expired, (raiden, message))

            elif type(message) == Delivered:
                assert isinstance(message, Delivered), MYPY_ANNOTATION
                pool.apply_async(self.handle_message_delivered, (raiden, message))

            elif type(message) == Processed:
                assert isinstance(message, Processed), MYPY_ANNOTATION
                pool.apply_async(self.handle_message_processed, (raiden, message))

            else:
                log.error(f"Unknown message cmdid {message.cmdid}")

        all_state_changes: List[StateChange] = list()
        for greenlet in joinall(set(pool), raise_error=True):
            all_state_changes.extend(greenlet.get())

        if all_state_changes:
            # Order balance proof messages, based the target channel and the
            # nonce. Because the balance proofs messages must be processed in
            # order, and there is no guarantee of the order of messages
            # (an asynchronous network is assumed) This reduces latency when a
            # balance proof is considered invalid because of a race with the
            # blockchain view of each node.
            def by_canonical_identifier(state_change: StateChange) -> Tuple[int, int]:
                if isinstance(state_change, BalanceProofStateChange):
                    balance_proof = state_change.balance_proof
                    return (
                        balance_proof.canonical_identifier.channel_identifier,
                        balance_proof.nonce,
                    )

                return (0, 0)

            all_state_changes.sort(key=by_canonical_identifier)

            raiden.handle_and_track_state_changes(all_state_changes)

    @staticmethod
    def handle_message_withdrawrequest(
        raiden: "RaidenService", message: WithdrawRequest  # pylint: disable=unused-argument
    ) -> List[StateChange]:
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
        return [withdraw_request]

    @staticmethod
    def handle_message_withdraw_confirmation(
        raiden: "RaidenService", message: WithdrawConfirmation  # pylint: disable=unused-argument
    ) -> List[StateChange]:
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
        return [withdraw]

    @staticmethod
    def handle_message_withdraw_expired(
        raiden: "RaidenService", message: WithdrawExpired  # pylint: disable=unused-argument
    ) -> List[StateChange]:
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
        )
        return [withdraw_expired]

    @staticmethod
    def handle_message_secretrequest(
        raiden: "RaidenService", message: SecretRequest  # pylint: disable=unused-argument
    ) -> List[StateChange]:
        assert message.sender, "message must be signed"
        secret_request = ReceiveSecretRequest(
            payment_identifier=message.payment_identifier,
            amount=message.amount,
            expiration=message.expiration,
            secrethash=message.secrethash,
            sender=message.sender,
        )
        return [secret_request]

    @staticmethod
    def handle_message_revealsecret(
        raiden: "RaidenService", message: RevealSecret  # pylint: disable=unused-argument
    ) -> List[StateChange]:
        assert message.sender, "message must be signed"
        secret_reveal = ReceiveSecretReveal(secret=message.secret, sender=message.sender)
        return [secret_reveal]

    @staticmethod
    def handle_message_unlock(
        raiden: "RaidenService", message: Unlock  # pylint: disable=unused-argument
    ) -> List[StateChange]:
        balance_proof = balanceproof_from_envelope(message)
        unlock = ReceiveUnlock(
            message_identifier=message.message_identifier,
            secret=message.secret,
            balance_proof=balance_proof,
            sender=balance_proof.sender,
        )
        return [unlock]

    @staticmethod
    def handle_message_lockexpired(
        raiden: "RaidenService", message: LockExpired  # pylint: disable=unused-argument
    ) -> List[StateChange]:
        balance_proof = balanceproof_from_envelope(message)
        lock_expired = ReceiveLockExpired(
            sender=balance_proof.sender,
            balance_proof=balance_proof,
            secrethash=message.secrethash,
            message_identifier=message.message_identifier,
        )
        return [lock_expired]

    @staticmethod
    def handle_message_refundtransfer(
        raiden: "RaidenService", message: RefundTransfer
    ) -> List[StateChange]:
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

        return state_changes

    @staticmethod
    def handle_message_lockedtransfer(
        raiden: "RaidenService", message: LockedTransfer  # pylint: disable=unused-argument
    ) -> List[StateChange]:
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
            secrethash=secrethash, block_identifier=BLOCK_ID_LATEST
        )
        if registered:
            log.warning(
                f"Ignoring received locked transfer with secrethash {to_hex(secrethash)} "
                f"since it is already registered in the secret registry"
            )
            return []

        assert message.sender, "Invalid message dispatched, it should be signed"

        if message.target == TargetAddress(raiden.address):
            raiden.immediate_health_check_for(Address(message.initiator))

            from_transfer = lockedtransfersigned_from_message(message)
            from_hop = HopState(
                node_address=message.sender,
                # pylint: disable=E1101
                channel_identifier=from_transfer.balance_proof.channel_identifier,
            )
            init_target_statechange = ActionInitTarget(
                from_hop=from_hop,
                transfer=from_transfer,
                balance_proof=from_transfer.balance_proof,
                sender=from_transfer.balance_proof.sender,  # pylint: disable=no-member
            )
            return [init_target_statechange]
        else:
            from_transfer = lockedtransfersigned_from_message(message)
            from_hop = HopState(
                message.sender,
                from_transfer.balance_proof.channel_identifier,  # pylint: disable=E1101
            )
            token_network_address = (
                from_transfer.balance_proof.token_network_address  # pylint: disable=E1101
            )
            route_states = routing.resolve_routes(
                routes=message.metadata.routes,
                token_network_address=token_network_address,
                chain_state=views.state_from_raiden(raiden),
            )
            init_mediator_statechange = ActionInitMediator(
                from_hop=from_hop,
                route_states=route_states,
                from_transfer=from_transfer,
                balance_proof=from_transfer.balance_proof,
                sender=from_transfer.balance_proof.sender,  # pylint: disable=no-member
            )
            return [init_mediator_statechange]

    @staticmethod
    def handle_message_processed(
        raiden: "RaidenService", message: Processed  # pylint: disable=unused-argument
    ) -> List[StateChange]:
        assert message.sender, "message must be signed"
        processed = ReceiveProcessed(message.sender, message.message_identifier)
        return [processed]

    @staticmethod
    def handle_message_delivered(
        raiden: "RaidenService", message: Delivered  # pylint: disable=unused-argument
    ) -> List[StateChange]:
        assert message.sender, "message must be signed"
        delivered = ReceiveDelivered(message.sender, message.delivered_message_identifier)
        return [delivered]
