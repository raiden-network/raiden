from math import inf

import structlog
from eth_utils import to_hex
from gevent import joinall
from gevent.pool import Pool

from raiden.constants import ABSENT_SECRET, BLOCK_ID_LATEST
from raiden.exceptions import InvalidSecret, ServiceRequestFailed
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
from raiden.transfer.utils.secret import decrypt_secret
from raiden.transfer.views import TransferRole
from raiden.utils.formatting import to_checksum_address
from raiden.utils.transfers import random_secret
from raiden.utils.typing import (
    TYPE_CHECKING,
    AddressMetadata,
    List,
    Optional,
    Set,
    TargetAddress,
    Tuple,
    Union,
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

        handler_map = {
            SecretRequest: self.handle_message_secretrequest,
            RevealSecret: self.handle_message_revealsecret,
            Unlock: self.handle_message_unlock,
            LockExpired: self.handle_message_lockexpired,
            RefundTransfer: self.handle_message_refundtransfer,
            LockedTransfer: self.handle_message_lockedtransfer,
            WithdrawRequest: self.handle_message_withdrawrequest,
            WithdrawConfirmation: self.handle_message_withdraw_confirmation,
            WithdrawExpired: self.handle_message_withdraw_expired,
            Delivered: self.handle_message_delivered,
            Processed: self.handle_message_processed,
        }

        for message in unique_messages:
            t_message = type(message)
            if t_message not in handler_map:
                log.error(f"Unknown message cmdid {message.cmdid}")
                continue
            pool.apply_async(handler_map[t_message], (raiden, message))

        all_state_changes: List[StateChange] = []
        for greenlet in joinall(set(pool), raise_error=True):
            all_state_changes.extend(greenlet.get())

        if all_state_changes:
            # Order balance proof messages, based the target channel and the
            # nonce. Because the balance proofs messages must be processed in
            # order, and there is no guarantee of the order of messages
            # (an asynchronous network is assumed) This reduces latency when a
            # balance proof is considered invalid because of a race with the
            # blockchain view of each node.
            def by_canonical_identifier(
                state_change: StateChange,
            ) -> Union[Tuple[int, int], Tuple[float, float]]:
                if isinstance(state_change, BalanceProofStateChange):
                    balance_proof = state_change.balance_proof
                    return (
                        balance_proof.canonical_identifier.channel_identifier,
                        balance_proof.nonce,
                    )
                elif isinstance(state_change, ReceiveSecretReveal):
                    # ReceiveSecretReveal depends on other state changes happening first.
                    return inf, inf
                return 0, 0

            all_state_changes.sort(key=by_canonical_identifier)
            raiden.handle_and_track_state_changes(all_state_changes)

    @staticmethod
    def handle_message_withdrawrequest(
        raiden: "RaidenService", message: WithdrawRequest  # pylint: disable=unused-argument
    ) -> List[StateChange]:
        assert message.sender, "message must be signed"

        sender_metadata: Optional[AddressMetadata] = None
        pfs_proxy = raiden.pfs_proxy
        # FIXME querying the PFS for the address-metadata directly after receiving a message
        #   should be optimized / factored out at a later point!
        try:
            sender_metadata = pfs_proxy.query_address_metadata(message.sender)
        except ServiceRequestFailed as ex:
            msg = f"PFS returned an error while trying to fetch user information: \n{ex}"
            log.warning(msg)
            sender_metadata = None

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
            sender_metadata=sender_metadata,
            coop_settle=message.coop_settle,
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
        # XXX: Not sure about this one. What should we do if the LockedTransfer has no
        #      route_states due to validation?
        # AFAIK the routes in the received transfer aren't relevant for the refund anyway.
        from_transfer = lockedtransfersigned_from_message(message=message)

        role = views.get_transfer_role(
            chain_state=chain_state, secrethash=from_transfer.lock.secrethash
        )

        state_changes: List[StateChange] = []

        if role == TransferRole.INITIATOR:
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

        from_transfer = lockedtransfersigned_from_message(message)

        if not message.metadata.routes:
            log.warning(
                f"Ignoring received locked transfer with secrethash {to_hex(secrethash)} "
                f"since there was no route information present."
            )
            return []

        from_hop = HopState(
            node_address=message.sender,
            # pylint: disable=E1101
            channel_identifier=from_transfer.balance_proof.channel_identifier,
        )

        balance_proof = from_transfer.balance_proof
        sender = from_transfer.balance_proof.sender

        if message.target == TargetAddress(raiden.address):
            encrypted_secret = message.metadata.secret
            if encrypted_secret is not None:
                try:
                    secret, amount, payment_identifier = decrypt_secret(
                        encrypted_secret, raiden.rpc_client.privkey
                    )
                    if (
                        from_transfer.lock.amount < amount
                        or from_transfer.payment_identifier != payment_identifier
                    ):
                        raise InvalidSecret
                    log.info("Using encrypted secret", sender=to_checksum_address(sender))
                    return [
                        ActionInitTarget(
                            from_hop=from_hop,
                            transfer=from_transfer,
                            balance_proof=balance_proof,
                            sender=sender,
                            received_valid_secret=True,
                        ),
                        ReceiveSecretReveal(secret=secret, sender=message.sender),
                    ]
                except InvalidSecret:
                    sender_addr = to_checksum_address(sender)
                    log.error("Ignoring invalid encrypted secret", sender=sender_addr)
            return [
                ActionInitTarget(
                    from_hop=from_hop,
                    transfer=from_transfer,
                    balance_proof=balance_proof,
                    sender=sender,
                )
            ]
        else:
            filtered_route_states = []
            for route_state in from_transfer.route_states:
                next_hop_address = route_state.hop_after(raiden.address)
                if not next_hop_address:
                    # Route is malformed or lacking forward information
                    continue
                channel_state = views.get_channelstate_by_token_network_and_partner(
                    chain_state=views.state_from_raiden(raiden),
                    token_network_address=from_transfer.balance_proof.token_network_address,
                    partner_address=next_hop_address,
                )
                if channel_state is not None:
                    filtered_route_states.append(route_state)
            return [
                ActionInitMediator(
                    from_hop=from_hop,
                    candidate_route_states=filtered_route_states,
                    from_transfer=from_transfer,
                    balance_proof=balance_proof,
                    sender=sender,
                )
            ]

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
