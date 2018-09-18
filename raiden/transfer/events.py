from eth_utils import to_canonical_address, to_checksum_address

from raiden.constants import UINT256_MAX
from raiden.transfer.architecture import (
    ContractSendEvent,
    ContractSendExpirableEvent,
    Event,
    SendMessageEvent,
)
from raiden.transfer.state import BalanceProofSignedState, BalanceProofUnsignedState
from raiden.utils import pex, serialization, sha3, typing

# pylint: disable=too-many-arguments,too-few-public-methods


class ContractSendChannelClose(ContractSendEvent):
    """ Event emitted to close the netting channel.
    This event is used when a node needs to prepare the channel to unlock
    on-chain.
    """

    def __init__(
            self,
            channel_identifier: typing.ChannelID,
            token_address: typing.TokenAddress,
            token_network_identifier: typing.TokenNetworkID,
            balance_proof: BalanceProofSignedState,
    ):
        self.channel_identifier = channel_identifier
        self.token_address = token_address
        self.token_network_identifier = token_network_identifier
        self.balance_proof = balance_proof

    def __repr__(self):
        return (
            '<ContractSendChannelClose channel:{} token:{} token_network:{} balance_proof:{}>'
        ).format(
            self.channel_identifier,
            pex(self.token_address),
            pex(self.token_network_identifier),
            self.balance_proof,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractSendChannelClose) and
            self.channel_identifier == other.channel_identifier and
            self.token_address == other.token_address and
            self.token_network_identifier == other.token_network_identifier and
            self.balance_proof == other.balance_proof
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        result = {
            'channel_identifier': self.channel_identifier,
            'token_address': to_checksum_address(self.token_address),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'balance_proof': self.balance_proof,

        }
        if self.balance_proof:
            result['balance_hash'] = serialization.serialize_bytes(self.balance_proof.balance_hash)
        return result

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'ContractSendChannelClose':
        restored = cls(
            channel_identifier=data['channel_identifier'],
            token_address=to_canonical_address(data['token_address']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            balance_proof=data['balance_proof'],
        )

        return restored


class ContractSendChannelSettle(ContractSendEvent):
    """ Event emitted if the netting channel must be settled. """

    def __init__(
            self,
            channel_identifier: typing.ChannelID,
            token_network_identifier: typing.TokenNetworkAddress,

    ):
        if not isinstance(channel_identifier, typing.T_ChannelID):
            raise ValueError('channel_identifier must be a ChannelID instance')

        if not isinstance(token_network_identifier, typing.T_TokenNetworkAddress):
            raise ValueError('token_network_identifier must be a TokenNetworkAddress instance')

        self.channel_identifier = channel_identifier
        self.token_network_identifier = token_network_identifier

    def __repr__(self):
        return '<ContractSendChannelSettle channel:{} token_network:{}>'.format(
            self.channel_identifier,
            pex(self.token_network_identifier),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractSendChannelSettle) and
            self.channel_identifier == other.channel_identifier and
            self.token_network_identifier == other.token_network_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        result = {
            'channel_identifier': self.channel_identifier,
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
        }

        return result

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'ContractSendChannelSettle':
        restored = cls(
            channel_identifier=data['channel_identifier'],
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
        )

        return restored


class ContractSendChannelUpdateTransfer(ContractSendExpirableEvent):
    """ Event emitted if the netting channel balance proof must be updated. """

    def __init__(
            self,
            expiration: typing.BlockExpiration,
            channel_identifier: typing.ChannelID,
            token_network_identifier: typing.TokenNetworkID,
            balance_proof: BalanceProofSignedState,
    ):
        super().__init__(expiration)

        self.channel_identifier = channel_identifier
        self.token_network_identifier = token_network_identifier
        self.balance_proof = balance_proof

    def __repr__(self):
        return (
            '<ContractSendChannelUpdateTransfer channel:{} token_network:{} balance_proof:{}>'
        ).format(
            self.channel_identifier,
            pex(self.token_network_identifier),
            self.balance_proof,
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

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        result = {
            'expiration': self.expiration,
            'channel_identifier': self.channel_identifier,
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'balance_proof': self.balance_proof,
        }
        if self.balance_proof:
            result['balance_hash'] = serialization.serialize_bytes(self.balance_proof.balance_hash)

        return result

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'ContractSendChannelUpdateTransfer':
        restored = cls(
            expiration=data['expiration'],
            channel_identifier=data['channel_identifier'],
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            balance_proof=data['balance_proof'],
        )

        return restored


class ContractSendChannelBatchUnlock(ContractSendEvent):
    """ Event emitted when the lock must be claimed on-chain. """

    def __init__(
            self,
            token_address: typing.TokenAddress,
            token_network_identifier: typing.TokenNetworkID,
            channel_identifier: typing.ChannelID,
            participant: typing.Address,
    ):
        self.token_address = token_address
        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier
        self.participant = participant

    def __repr__(self):
        return (
            '<ContractSendChannelBatchUnlock '
            'token_address: {} token_network_id:{} channel:{} participant:{}'
            '>'
        ).format(
            pex(self.token_address),
            pex(self.token_network_identifier),
            self.channel_identifier,
            pex(self.participant),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractSendChannelBatchUnlock) and
            self.token_address == other.token_address and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier and
            self.participant == other.participant
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        result = {
            'token_address': to_checksum_address(self.token_address),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'channel_identifier': self.channel_identifier,
            'participant': to_checksum_address(self.participant),
        }

        return result

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'ContractSendChannelBatchUnlock':
        restored = cls(
            token_address=to_canonical_address(data['token_address']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            channel_identifier=data['channel_identifier'],
            participant=to_canonical_address(data['participant']),
        )

        return restored


class ContractSendSecretReveal(ContractSendExpirableEvent):
    """ Event emitted when the lock must be claimed on-chain. """

    def __init__(self, expiration: typing.BlockExpiration, secret: typing.Secret):
        if not isinstance(secret, typing.T_Secret):
            raise ValueError('secret must be a Secret instance')

        super().__init__(expiration)
        self.secret = secret

    def __repr__(self):
        secrethash: typing.SecretHash = typing.SecretHash(sha3(self.secret))
        return '<ContractSendSecretReveal secrethash:{}>'.format(secrethash)

    def __eq__(self, other):
        return (
            isinstance(other, ContractSendSecretReveal) and
            self.secret == other.secret and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        result = {
            'expiration': self.expiration,
            'secret': serialization.serialize_bytes(self.secret),
        }

        return result

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'ContractSendSecretReveal':
        restored = cls(
            expiration=data['expiration'],
            secret=serialization.deserialize_bytes(data['secret']),
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
            payment_network_identifier: typing.PaymentNetworkID,
            token_network_identifier: typing.TokenNetworkID,
            identifier: typing.PaymentID,
            amount: typing.TokenAmount,
            target: typing.TargetAddress,
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

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        result = {
            'payment_network_identifier': to_checksum_address(self.payment_network_identifier),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'identifier': self.identifier,
            'amount': self.amount,
            'target': to_checksum_address(self.target),
        }

        return result

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'EventPaymentSentSuccess':
        restored = cls(
            payment_network_identifier=to_canonical_address(data['payment_network_identifier']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            identifier=data['identifier'],
            amount=data['amount'],
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
            payment_network_identifier: typing.PaymentNetworkID,
            token_network_identifier: typing.TokenNetworkID,
            identifier: typing.PaymentID,
            target: typing.TargetAddress,
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
            self.target,
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

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        result = {
            'payment_network_identifier': to_checksum_address(self.payment_network_identifier),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'identifier': self.identifier,
            'target': to_checksum_address(self.target),
            'reason': self.reason,
        }

        return result

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'EventPaymentSentFailed':
        restored = cls(
            payment_network_identifier=to_canonical_address(data['payment_network_identifier']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            identifier=data['identifier'],
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
            payment_network_identifier: typing.PaymentNetworkID,
            token_network_identifier: typing.TokenNetworkID,
            identifier: typing.PaymentID,
            amount: typing.TokenAmount,
            initiator: typing.InitiatorAddress,
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

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        result = {
            'payment_network_identifier': to_checksum_address(self.payment_network_identifier),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'identifier': self.identifier,
            'amount': self.amount,
            'initiator': to_checksum_address(self.initiator),
        }

        return result

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'EventPaymentReceivedSuccess':
        restored = cls(
            payment_network_identifier=to_canonical_address(data['payment_network_identifier']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            identifier=data['identifier'],
            amount=data['amount'],
            initiator=to_canonical_address(data['initiator']),
        )

        return restored


class EventTransferReceivedInvalidDirectTransfer(Event):
    """ Event emitted when an invalid direct transfer is received. """

    def __init__(self, identifier: typing.PaymentID, reason: str):
        self.identifier = identifier
        self.reason = reason

    def __repr__(self):
        return '<EventTransferReceivedInvalidDirectTransfer identifier:{} reason:{}>'.format(
            self.identifier,
            self.reason,
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventTransferReceivedInvalidDirectTransfer) and
            self.identifier == other.identifier and
            self.reason == other.reason
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        result = {
            'identifier': self.identifier,
            'reason': self.reason,
        }

        return result

    @classmethod
    def from_dict(
            cls,
            data: typing.Dict[str, typing.Any],
    )-> 'EventTransferReceivedInvalidDirectTransfer':
        restored = cls(
            identifier=data['identifier'],
            reason=data['reason'],
        )

        return restored


class SendDirectTransfer(SendMessageEvent):
    """ Event emitted when a direct transfer message must be sent. """

    def __init__(
            self,
            recipient: typing.Address,
            channel_identifier: typing.ChannelID,
            message_identifier: typing.MessageID,
            payment_identifier: typing.PaymentID,
            balance_proof: BalanceProofUnsignedState,
            token_address: typing.TokenAddress,
    ):

        super().__init__(recipient, channel_identifier, message_identifier)

        self.payment_identifier = payment_identifier
        self.balance_proof = balance_proof
        self.token = token_address

    def __repr__(self):
        return (
            '<'
            'SendDirectTransfer msgid:{} paymentid:{} balance_proof:{}'
            ' token:{} recipient:{}'
            '>'
        ).format(
            self.message_identifier,
            self.payment_identifier,
            self.balance_proof,
            pex(self.token),
            pex(self.recipient),
        )

    def __eq__(self, other):
        return (
            isinstance(other, SendDirectTransfer) and
            self.payment_identifier == other.payment_identifier and
            self.balance_proof == other.balance_proof and
            self.token == other.token and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        result = {
            'recipient': to_checksum_address(self.recipient),
            'channel_identifier': self.queue_identifier.channel_identifier,
            'message_identifier': self.message_identifier,
            'payment_identifier': self.payment_identifier,
            'balance_proof': self.balance_proof,
            'token_address': to_checksum_address(self.token),
        }
        if self.balance_proof:
            result['balance_hash'] = serialization.serialize_bytes(self.balance_proof.balance_hash)

        return result

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'SendDirectTransfer':
        restored = cls(
            recipient=to_canonical_address(data['recipient']),
            channel_identifier=data['channel_identifier'],
            message_identifier=data['message_identifier'],
            payment_identifier=data['payment_identifier'],
            balance_proof=data['balance_proof'],
            token_address=to_canonical_address(data['token_address']),
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

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        result = {
            'recipient': to_checksum_address(self.recipient),
            'channel_identifier': self.queue_identifier.channel_identifier,
            'message_identifier': self.message_identifier,
        }

        return result

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'SendProcessed':
        restored = cls(
            recipient=to_canonical_address(data['recipient']),
            channel_identifier=data['channel_identifier'],
            message_identifier=data['message_identifier'],
        )

        return restored
