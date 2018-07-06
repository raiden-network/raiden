from raiden.constants import UINT256_MAX
from raiden.transfer.architecture import (
    Event,
    SendMessageEvent,
)
from raiden.transfer.state import BalanceProofSignedState, BalanceProofUnsignedState
from raiden.utils import pex, typing, sha3
# pylint: disable=too-many-arguments,too-few-public-methods


class ContractSendChannelClose(Event):
    """ Event emitted to close the netting channel.
    This event is used when a node needs to prepare the channel to unlock
    on-chain.
    """

    def __init__(self, channel_identifier, token_address, token_network_identifier, balance_proof):
        self.channel_identifier = channel_identifier
        self.token_address = token_address
        self.token_network_identifier = token_network_identifier
        self.balance_proof = balance_proof

    def __repr__(self):
        return (
            '<ContractSendChannelClose channel:{} token:{} token_network:{} balance_proof:{}>'
        ).format(
            pex(self.channel_identifier),
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


class ContractSendChannelSettle(Event):
    """ Event emitted if the netting channel must be settled. """

    def __init__(
            self,
            channel_identifier: typing.ChannelID,
            token_network_identifier: typing.TokenNetworkAddress,
            our_balance_proof: typing.Union[
                BalanceProofSignedState,
                BalanceProofUnsignedState,
                None,
            ],
            partner_balance_proof: typing.Union[
                BalanceProofSignedState,
                BalanceProofUnsignedState,
                None,
            ],
    ):
        if not isinstance(channel_identifier, typing.T_ChannelID):
            raise ValueError('channel_identifier must be a ChannelID instance')

        if not isinstance(token_network_identifier, typing.T_TokenNetworkAddress):
            raise ValueError('token_network_identifier must be a TokenNetworkAddress instance')

        if our_balance_proof and not isinstance(
            our_balance_proof,
            (BalanceProofUnsignedState, BalanceProofSignedState),
        ):
            raise ValueError('our_balance_proof must be a BalanceProofSignedState instance')

        if partner_balance_proof and not isinstance(
            partner_balance_proof,
            (BalanceProofUnsignedState, BalanceProofSignedState),
        ):
            raise ValueError('partner_balance_proof must be a BalanceProofSignedState instance')

        self.channel_identifier = channel_identifier
        self.token_network_identifier = token_network_identifier
        self.our_balance_proof = our_balance_proof
        self.partner_balance_proof = partner_balance_proof

    def __repr__(self):
        return '<ContractSendChannelSettle channel:{} token_network:{}>'.format(
            pex(self.channel_identifier),
            pex(self.token_network_identifier),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractSendChannelSettle) and
            self.channel_identifier == other.channel_identifier and
            self.token_network_identifier == other.token_network_identifier and
            self.our_balance_proof == other.our_balance_proof and
            self.partner_balance_proof == other.partner_balance_proof
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractSendChannelUpdateTransfer(Event):
    """ Event emitted if the netting channel balance proof must be updated. """

    def __init__(self, channel_identifier, token_network_identifier, balance_proof):
        self.channel_identifier = channel_identifier
        self.token_network_identifier = token_network_identifier
        self.balance_proof = balance_proof

    def __repr__(self):
        return (
            '<ContractSendChannelUpdateTransfer channel:{} token_network:{} balance_proof:{}>'
        ).format(
            pex(self.channel_identifier),
            pex(self.token_network_identifier),
            self.balance_proof,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractSendChannelUpdateTransfer) and
            self.channel_identifier == other.channel_identifier and
            self.token_network_identifier == other.token_network_identifier and
            self.balance_proof == other.balance_proof
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractSendChannelBatchUnlock(Event):
    """ Event emitted when the lock must be claimed on-chain. """

    def __init__(self, token_network_identifier, channel_identifier, merkle_treee_leaves):
        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier
        self.merkle_treee_leaves = merkle_treee_leaves

    def __repr__(self):
        return '<ContractSendChannelBatchUnlock channel:{} merkle_treee_leaves:{}>'.format(
            pex(self.token_network_identifier),
            pex(self.channel_identifier),
            self.merkle_treee_leaves,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractSendChannelBatchUnlock) and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier and
            self.merkle_treee_leaves == other.merkle_treee_leaves
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractSendSecretReveal(Event):
    """ Event emitted when the lock must be claimed on-chain. """

    def __init__(self, secret: typing.Secret):
        if not isinstance(secret, typing.T_Secret):
            raise ValueError('secret must be a Secret instance')

        self.secret = secret

    def __repr__(self):
        secrethash: typing.SecretHash = typing.SecretHash(sha3(self.secret))
        return '<ContractSendSecretReveal secrethash:{}>'.format(secrethash)

    def __eq__(self, other):
        return (
            isinstance(other, ContractSendSecretReveal) and
            self.secret == other.secret
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class EventTransferSentSuccess(Event):
    """ Event emitted by the initiator when a transfer is considered sucessful.

    A transfer is considered sucessful when the initiator's payee hop sends the
    reveal secret message, assuming that each hop in the mediator chain has
    also learned the secret and unlocked its token off-chain or on-chain.

    This definition of sucessful is used to avoid the following corner case:

    - The reveal secret message is sent, since the network is unreliable and we
      assume byzantine behavior the message is considered delivered without an
      acknowledgement.
    - The transfer is considered sucessful because of the above.
    - The reveal secret message was not delivered because of actual network
      problems.
    - The lock expires and an EventUnlockFailed follows, contradicting the
      EventTransferSentSuccess.

    Note:
        Mediators cannot use this event, since an off-chain unlock may be locally
        sucessful but there is no knowledge about the global transfer.
    """

    def __init__(self, identifier, amount, target):
        self.identifier = identifier
        self.amount = amount
        self.target = target

    def __repr__(self):
        return '<EventTransferSentSuccess identifier:{} amount:{} target:{}>'.format(
            self.identifier,
            self.amount,
            pex(self.target),
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventTransferSentSuccess) and
            self.identifier == other.identifier and
            self.amount == other.amount and
            self.target == other.target
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class EventTransferSentFailed(Event):
    """ Event emitted by the payer when a transfer has failed.

    Note:
        Mediators cannot use this event since they don't know when a transfer
        has failed, they may infer about lock successes and failures.
    """

    def __init__(self, identifier, reason):
        self.identifier = identifier
        self.reason = reason

    def __repr__(self):
        return '<EventTransferSentFailed id:{} reason:{}>'.format(
            self.identifier,
            self.reason,
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventTransferSentFailed) and
            self.identifier == other.identifier and
            self.reason == other.reason
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class EventTransferReceivedSuccess(Event):
    """ Event emitted when a payee has received a payment.

    Note:
        A payee knows if a lock claim has failed, but this is not sufficient
        information to deduce when a transfer has failed, because the initiator may
        try again at a different time and/or with different routes, for this reason
        there is no correspoding `EventTransferReceivedFailed`.
    """

    def __init__(self, identifier, amount, initiator):
        if amount < 0:
            raise ValueError('transferred_amount cannot be negative')

        if amount > UINT256_MAX:
            raise ValueError('transferred_amount is too large')

        self.identifier = identifier
        self.amount = amount
        self.initiator = initiator

    def __repr__(self):
        return '<EventTransferReceivedSuccess identifier:{} amount:{} initiator:{}>'.format(
            self.identifier,
            self.amount,
            pex(self.initiator),
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventTransferReceivedSuccess) and
            self.identifier == other.identifier and
            self.amount == other.amount and
            self.initiator == other.initiator
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class EventTransferReceivedInvalidDirectTransfer(Event):
    """ Event emitted when an invalid direct transfer is received. """

    def __init__(self, identifier, reason):
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


class SendDirectTransfer(SendMessageEvent):
    """ Event emitted when a direct transfer message must be sent. """

    def __init__(
            self,
            recipient,
            queue_name,
            message_identifier,
            payment_identifier,
            balance_proof,
            token,
    ):

        super().__init__(recipient, queue_name, message_identifier)

        self.payment_identifier = payment_identifier
        self.balance_proof = balance_proof
        self.token = token

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
            self.message_identifier == other.message_identifier and
            self.payment_identifier == other.payment_identifier and
            self.balance_proof == other.balance_proof and
            self.token == other.token and
            self.recipient == other.recipient
        )

    def __ne__(self, other):
        return not self.__eq__(other)


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
            self.message_identifier == other.message_identifier and
            self.recipient == other.recipient
        )

    def __ne__(self, other):
        return not self.__eq__(other)
