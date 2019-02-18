from eth_utils import to_canonical_address, to_checksum_address

from raiden.constants import UINT256_MAX
from raiden.transfer.architecture import (
    ContractSendEvent,
    ContractSendExpirableEvent,
    Event,
    SendMessageEvent,
)
from raiden.transfer.state import BalanceProofSignedState
from raiden.utils import pex, serialization, sha3
from raiden.utils.serialization import deserialize_bytes, serialize_bytes
from raiden.utils.typing import (
    Address,
    Any,
    BlockExpiration,
    BlockHash,
    ChannelID,
    Dict,
    InitiatorAddress,
    Optional,
    PaymentID,
    PaymentNetworkID,
    Secret,
    SecretHash,
    T_ChannelID,
    T_Secret,
    T_TokenNetworkAddress,
    TargetAddress,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkID,
)

# pylint: disable=too-many-arguments,too-few-public-methods


class ContractSendChannelClose(ContractSendEvent):
    """ Event emitted to close the netting channel.
    This event is used when a node needs to prepare the channel to unlock
    on-chain.
    """

    def __init__(
            self,
            channel_identifier: ChannelID,
            token_address: TokenAddress,
            token_network_identifier: TokenNetworkID,
            balance_proof: Optional[BalanceProofSignedState],
            triggered_by_block_hash: BlockHash,
    ):
        super().__init__(triggered_by_block_hash)
        self.channel_identifier = channel_identifier
        self.token_address = token_address
        self.token_network_identifier = token_network_identifier
        self.balance_proof = balance_proof

    def __repr__(self):
        return (
            '<ContractSendChannelClose channel:{} token:{} token_network:{} '
            'balance_proof:{} triggered_by_block_hash:{}>'
        ).format(
            self.channel_identifier,
            pex(self.token_address),
            pex(self.token_network_identifier),
            self.balance_proof,
            pex(self.triggered_by_block_hash),
        )

    def __eq__(self, other):
        return (
            super().__eq__(other) and
            isinstance(other, ContractSendChannelClose) and
            self.channel_identifier == other.channel_identifier and
            self.token_address == other.token_address and
            self.token_network_identifier == other.token_network_identifier and
            self.balance_proof == other.balance_proof
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'channel_identifier': str(self.channel_identifier),
            'token_address': to_checksum_address(self.token_address),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'balance_proof': self.balance_proof,
            'triggered_by_block_hash': serialize_bytes(self.triggered_by_block_hash),

        }
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractSendChannelClose':
        restored = cls(
            channel_identifier=ChannelID(int(data['channel_identifier'])),
            token_address=to_canonical_address(data['token_address']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            balance_proof=data['balance_proof'],
            triggered_by_block_hash=BlockHash(deserialize_bytes(data['triggered_by_block_hash'])),
        )

        return restored


class ContractSendChannelSettle(ContractSendEvent):
    """ Event emitted if the netting channel must be settled. """

    def __init__(
            self,
            channel_identifier: ChannelID,
            token_network_identifier: TokenNetworkAddress,
            triggered_by_block_hash: BlockHash,
    ):
        super().__init__(triggered_by_block_hash)
        if not isinstance(channel_identifier, T_ChannelID):
            raise ValueError('channel_identifier must be a ChannelID instance')

        if not isinstance(token_network_identifier, T_TokenNetworkAddress):
            raise ValueError('token_network_identifier must be a TokenNetworkAddress instance')

        self.channel_identifier = channel_identifier
        self.token_network_identifier = token_network_identifier

    def __repr__(self):
        return (
            '<ContractSendChannelSettle channel:{} token_network:{} '
            'triggered_by_block_hash:{}>'.format(
                self.channel_identifier,
                pex(self.token_network_identifier),
                pex(self.triggered_by_block_hash),
            )
        )

    def __eq__(self, other):
        return (
            super().__eq__(other) and
            isinstance(other, ContractSendChannelSettle) and
            self.channel_identifier == other.channel_identifier and
            self.token_network_identifier == other.token_network_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'channel_identifier': str(self.channel_identifier),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'triggered_by_block_hash': serialize_bytes(self.triggered_by_block_hash),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractSendChannelSettle':
        restored = cls(
            channel_identifier=ChannelID(int(data['channel_identifier'])),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            triggered_by_block_hash=BlockHash(deserialize_bytes(data['triggered_by_block_hash'])),
        )

        return restored


class ContractSendChannelUpdateTransfer(ContractSendExpirableEvent):
    """ Event emitted if the netting channel balance proof must be updated. """

    def __init__(
            self,
            expiration: BlockExpiration,
            channel_identifier: ChannelID,
            token_network_identifier: TokenNetworkID,
            balance_proof: BalanceProofSignedState,
            triggered_by_block_hash: BlockHash,
    ):
        super().__init__(triggered_by_block_hash, expiration)

        self.channel_identifier = channel_identifier
        self.token_network_identifier = token_network_identifier
        self.balance_proof = balance_proof

    def __repr__(self):
        return (
            '<ContractSendChannelUpdateTransfer channel:{} token_network:{} '
            'balance_proof:{} triggered_by_block_hash:{}>'
        ).format(
            self.channel_identifier,
            pex(self.token_network_identifier),
            self.balance_proof,
            pex(self.triggered_by_block_hash),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractSendChannelUpdateTransfer) and
            self.channel_identifier == other.channel_identifier and
            self.token_network_identifier == other.token_network_identifier and
            self.balance_proof == other.balance_proof and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'expiration': str(self.expiration),
            'channel_identifier': str(self.channel_identifier),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'balance_proof': self.balance_proof,
            'triggered_by_block_hash': serialize_bytes(self.triggered_by_block_hash),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractSendChannelUpdateTransfer':
        restored = cls(
            expiration=int(data['expiration']),
            channel_identifier=ChannelID(int(data['channel_identifier'])),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            balance_proof=data['balance_proof'],
            triggered_by_block_hash=BlockHash(deserialize_bytes(data['triggered_by_block_hash'])),
        )

        return restored


class ContractSendChannelBatchUnlock(ContractSendEvent):
    """ Event emitted when the lock must be claimed on-chain. """

    def __init__(
            self,
            token_address: TokenAddress,
            token_network_identifier: TokenNetworkID,
            channel_identifier: ChannelID,
            participant: Address,
            triggered_by_block_hash: BlockHash,
    ):
        super().__init__(triggered_by_block_hash)
        self.token_address = token_address
        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier
        self.participant = participant

    def __repr__(self):
        return (
            '<ContractSendChannelBatchUnlock token_address: {} token_network_id:{} '
            'channel:{} participant:{} triggered_by_block_hash:{}'
            '>'
        ).format(
            pex(self.token_address),
            pex(self.token_network_identifier),
            self.channel_identifier,
            pex(self.participant),
            pex(self.triggered_by_block_hash),
        )

    def __eq__(self, other):
        return (
            super().__eq__(other) and
            isinstance(other, ContractSendChannelBatchUnlock) and
            self.token_address == other.token_address and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier and
            self.participant == other.participant
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'token_address': to_checksum_address(self.token_address),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'channel_identifier': str(self.channel_identifier),
            'participant': to_checksum_address(self.participant),
            'triggered_by_block_hash': serialize_bytes(self.triggered_by_block_hash),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractSendChannelBatchUnlock':
        restored = cls(
            token_address=to_canonical_address(data['token_address']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            channel_identifier=ChannelID(int(data['channel_identifier'])),
            participant=to_canonical_address(data['participant']),
            triggered_by_block_hash=BlockHash(deserialize_bytes(data['triggered_by_block_hash'])),
        )

        return restored


class ContractSendSecretReveal(ContractSendExpirableEvent):
    """ Event emitted when the lock must be claimed on-chain. """

    def __init__(
            self,
            expiration: BlockExpiration,
            secret: Secret,
            triggered_by_block_hash: BlockHash,
    ):
        if not isinstance(secret, T_Secret):
            raise ValueError('secret must be a Secret instance')

        super().__init__(triggered_by_block_hash, expiration)
        self.secret = secret

    def __repr__(self):
        secrethash: SecretHash = SecretHash(sha3(self.secret))
        return (
            '<ContractSendSecretReveal secrethash:{} triggered_by_block_hash:{}>'
        ).format(secrethash, pex(self.triggered_by_block_hash))

    def __eq__(self, other):
        return (
            isinstance(other, ContractSendSecretReveal) and
            self.secret == other.secret and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'expiration': str(self.expiration),
            'secret': serialization.serialize_bytes(self.secret),
            'triggered_by_block_hash': serialize_bytes(self.triggered_by_block_hash),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractSendSecretReveal':
        restored = cls(
            expiration=BlockExpiration(int(data['expiration'])),
            secret=Secret(serialization.deserialize_bytes(data['secret'])),
            triggered_by_block_hash=BlockHash(deserialize_bytes(data['triggered_by_block_hash'])),
        )

        return restored


class EventPaymentSentSuccess(Event):
    """ Event emitted by the initiator when a transfer is considered successful.

    A transfer is considered successful when the initiator's payee hop sends the
    reveal secret message, assuming that each hop in the mediator chain has
    also learned the secret and unlocked its token off-chain or on-chain.

    This definition of successful is used to avoid the following corner case:

    - The reveal secret message is sent, since the network is unreliable and we
      assume byzantine behavior the message is considered delivered without an
      acknowledgement.
    - The transfer is considered successful because of the above.
    - The reveal secret message was not delivered because of actual network
      problems.
    - The lock expires and an EventUnlockFailed follows, contradicting the
      EventPaymentSentSuccess.

    Note:
        Mediators cannot use this event, since an off-chain unlock may be locally
        successful but there is no knowledge about the global transfer.
    """

    def __init__(
            self,
            payment_network_identifier: PaymentNetworkID,
            token_network_identifier: TokenNetworkID,
            identifier: PaymentID,
            amount: TokenAmount,
            target: TargetAddress,
    ):
        self.payment_network_identifier = payment_network_identifier
        self.token_network_identifier = token_network_identifier
        self.identifier = identifier
        self.amount = amount
        self.target = target

    def __repr__(self):
        return (
            '<'
            'EventPaymentSentSuccess payment_network_identifier:{} '
            'token_network_identifier:{} '
            'identifier:{} amount:{} '
            'target:{}'
            '>'
        ).format(
            pex(self.payment_network_identifier),
            pex(self.token_network_identifier),
            self.identifier,
            self.amount,
            pex(self.target),
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventPaymentSentSuccess) and
            self.identifier == other.identifier and
            self.amount == other.amount and
            self.target == other.target and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_network_identifier == other.token_network_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'payment_network_identifier': to_checksum_address(self.payment_network_identifier),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'identifier': str(self.identifier),
            'amount': str(self.amount),
            'target': to_checksum_address(self.target),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EventPaymentSentSuccess':
        restored = cls(
            payment_network_identifier=to_canonical_address(data['payment_network_identifier']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            identifier=int(data['identifier']),
            amount=int(data['amount']),
            target=to_canonical_address(data['target']),
        )

        return restored


class EventPaymentSentFailed(Event):
    """ Event emitted by the payer when a transfer has failed.

    Note:
        Mediators cannot use this event since they don't know when a transfer
        has failed, they may infer about lock successes and failures.
    """

    def __init__(
            self,
            payment_network_identifier: PaymentNetworkID,
            token_network_identifier: TokenNetworkID,
            identifier: PaymentID,
            target: TargetAddress,
            reason: str,
    ):
        self.payment_network_identifier = payment_network_identifier
        self.token_network_identifier = token_network_identifier
        self.identifier = identifier
        self.target = target
        self.reason = reason

    def __repr__(self):
        return (
            '<'
            'EventPaymentSentFailed payment_network_identifier:{} '
            'token_network_identifier:{} '
            'id:{} target:{} reason:{} '
            '>'
        ).format(
            pex(self.payment_network_identifier),
            pex(self.token_network_identifier),
            self.identifier,
            pex(self.target),
            self.reason,
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventPaymentSentFailed) and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_network_identifier == other.token_network_identifier and
            self.identifier == other.identifier and
            self.target == other.target and
            self.reason == other.reason
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'payment_network_identifier': to_checksum_address(self.payment_network_identifier),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'identifier': str(self.identifier),
            'target': to_checksum_address(self.target),
            'reason': self.reason,
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EventPaymentSentFailed':
        restored = cls(
            payment_network_identifier=to_canonical_address(data['payment_network_identifier']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            identifier=int(data['identifier']),
            target=to_canonical_address(data['target']),
            reason=data['reason'],
        )

        return restored


class EventPaymentReceivedSuccess(Event):
    """ Event emitted when a payee has received a payment.

    Note:
        A payee knows if a lock claim has failed, but this is not sufficient
        information to deduce when a transfer has failed, because the initiator may
        try again at a different time and/or with different routes, for this reason
        there is no correspoding `EventTransferReceivedFailed`.
    """

    def __init__(
            self,
            payment_network_identifier: PaymentNetworkID,
            token_network_identifier: TokenNetworkID,
            identifier: PaymentID,
            amount: TokenAmount,
            initiator: InitiatorAddress,
    ):
        if amount < 0:
            raise ValueError('transferred_amount cannot be negative')

        if amount > UINT256_MAX:
            raise ValueError('transferred_amount is too large')

        self.identifier = identifier
        self.amount = amount
        self.initiator = initiator
        self.payment_network_identifier = payment_network_identifier
        self.token_network_identifier = token_network_identifier

    def __repr__(self):
        return (
            '<'
            'EventPaymentReceivedSuccess payment_network_identifier:{} '
            'token_network_identifier:{} identifier:{} '
            'amount:{} initiator:{} '
            '>'
        ).format(
            pex(self.payment_network_identifier),
            pex(self.token_network_identifier),
            self.identifier,
            self.amount,
            pex(self.initiator),
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventPaymentReceivedSuccess) and
            self.identifier == other.identifier and
            self.amount == other.amount and
            self.initiator == other.initiator and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_network_identifier == other.token_network_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'payment_network_identifier': to_checksum_address(self.payment_network_identifier),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'identifier': str(self.identifier),
            'amount': str(self.amount),
            'initiator': to_checksum_address(self.initiator),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EventPaymentReceivedSuccess':
        restored = cls(
            payment_network_identifier=to_canonical_address(data['payment_network_identifier']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            identifier=int(data['identifier']),
            amount=int(data['amount']),
            initiator=to_canonical_address(data['initiator']),
        )

        return restored


class EventInvalidReceivedTransferRefund(Event):
    """ Event emitted when an invalid refund transfer is received. """

    def __init__(self, payment_identifier: PaymentID, reason: str):
        self.payment_identifier = payment_identifier
        self.reason = reason

    def __repr__(self):
        return (
            f'<'
            f'EventInvalidReceivedTransferRefund '
            f'payment_identifier:{self.payment_identifier} '
            f'reason:{self.reason}'
            f'>'
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventInvalidReceivedTransferRefund) and
            self.payment_identifier == other.payment_identifier and
            self.reason == other.reason
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'payment_identifier': str(self.payment_identifier),
            'reason': self.reason,
        }

        return result

    @classmethod
    def from_dict(
            cls,
            data: Dict[str, Any],
    ) -> 'EventInvalidReceivedTransferRefund':
        restored = cls(
            payment_identifier=int(data['payment_identifier']),
            reason=data['reason'],
        )

        return restored


class EventInvalidReceivedLockExpired(Event):
    """ Event emitted when an invalid lock expired message is received. """

    def __init__(self, secrethash: SecretHash, reason: str):
        self.secrethash = secrethash
        self.reason = reason

    def __repr__(self):
        return (
            f'<'
            f'EventInvalidReceivedLockExpired '
            f'secrethash:{pex(self.secrethash)} '
            f'reason:{self.reason}'
            f'>'
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventInvalidReceivedLockExpired) and
            self.secrethash == other.secrethash and
            self.reason == other.reason
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'secrethash': serialization.serialize_bytes(self.secrethash),
            'reason': self.reason,
        }

        return result

    @classmethod
    def from_dict(
            cls,
            data: Dict[str, Any],
    ) -> 'EventInvalidReceivedLockExpired':
        restored = cls(
            secrethash=serialization.deserialize_bytes(data['secrethash']),
            reason=data['reason'],
        )

        return restored


class EventInvalidReceivedLockedTransfer(Event):
    """ Event emitted when an invalid locked transfer is received. """

    def __init__(self, payment_identifier: PaymentID, reason: str):
        self.payment_identifier = payment_identifier
        self.reason = reason

    def __repr__(self):
        return (
            f'<'
            f'EventInvalidReceivedLockedTransfer '
            f'payment_identifier:{self.payment_identifier} '
            f'reason:{self.reason}'
            f'>'
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventInvalidReceivedLockedTransfer) and
            self.payment_identifier == other.payment_identifier and
            self.reason == other.reason
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'payment_identifier': str(self.payment_identifier),
            'reason': self.reason,
        }

        return result

    @classmethod
    def from_dict(
            cls,
            data: Dict[str, Any],
    ) -> 'EventInvalidReceivedLockedTransfer':
        restored = cls(
            payment_identifier=int(data['payment_identifier']),
            reason=data['reason'],
        )

        return restored


class EventInvalidReceivedUnlock(Event):
    """ Event emitted when an invalid unlock message is received. """

    def __init__(self, secrethash: SecretHash, reason: str):
        self.secrethash = secrethash
        self.reason = reason

    def __repr__(self):
        return (
            f'<'
            f'EventInvalidReceivedUnlock '
            f'secrethash:{pex(self.secrethash)} '
            f'reason:{self.reason}'
            f'>'
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventInvalidReceivedUnlock) and
            self.secrethash == other.secrethash and
            self.reason == other.reason
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'secrethash': serialization.serialize_bytes(self.secrethash),
            'reason': self.reason,
        }

        return result

    @classmethod
    def from_dict(
            cls,
            data: Dict[str, Any],
    ) -> 'EventInvalidReceivedUnlock':
        restored = cls(
            secrethash=serialization.deserialize_bytes(data['secrethash']),
            reason=data['reason'],
        )

        return restored


class SendProcessed(SendMessageEvent):
    def __repr__(self):
        return (
            '<SendProcessed confirmed_msgid:{} recipient:{}>'
        ).format(
            self.message_identifier,
            pex(self.recipient),
        )

    def __eq__(self, other):
        return (
            isinstance(other, SendProcessed) and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'recipient': to_checksum_address(self.recipient),
            'channel_identifier': str(self.queue_identifier.channel_identifier),
            'message_identifier': str(self.message_identifier),
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SendProcessed':
        restored = cls(
            recipient=to_canonical_address(data['recipient']),
            channel_identifier=ChannelID(int(data['channel_identifier'])),
            message_identifier=int(data['message_identifier']),
        )

        return restored
