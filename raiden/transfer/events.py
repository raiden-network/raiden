# -*- coding: utf-8 -*-
from raiden.transfer.architecture import Event
from raiden.utils import pex
# pylint: disable=too-many-arguments,too-few-public-methods


class ContractSendChannelClose(Event):
    """ Event emitted to close the netting channel.
    This event is used when a node needs to prepare the channel to withdraw
    on-chain.
    """

    def __init__(self, channel_identifier, token_address, balance_proof):
        self.channel_identifier = channel_identifier
        self.token_address = token_address
        self.balance_proof = balance_proof

    def __str__(self):
        return '<ContractSendChannelClose channel:{} token:{} balance_proof:{}>'.format(
            pex(self.channel_identifier),
            pex(self.token_address),
            self.balance_proof,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractSendChannelClose) and
            self.channel_identifier == other.channel_identifier and
            self.token_address == other.token_address and
            self.balance_proof == other.balance_proof
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractSendChannelSettle(Event):
    """ Event emitted if the netting channel must be settled. """

    def __init__(self, channel_identifier):
        self.channel_identifier = channel_identifier

    def __str__(self):
        return '<ContractSendChannelSettle channel:{}>'.format(
            pex(self.channel_identifier)
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractSendChannelSettle) and
            self.channel_identifier == other.channel_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractSendChannelUpdateTransfer(Event):
    """ Event emitted if the netting channel balance proof must be updated. """

    def __init__(self, channel_identifier, balance_proof):
        self.channel_identifier = channel_identifier
        self.balance_proof = balance_proof

    def __str__(self):
        return '<ContractSendChannelUpdateTransfer channel:{} balance_proof:{}>'.format(
            pex(self.channel_identifier),
            self.balance_proof,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractSendChannelUpdateTransfer) and
            self.channel_identifier == other.channel_identifier and
            self.balance_proof == other.balance_proof
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractSendChannelWithdraw(Event):
    """ Event emitted when the lock must be withdrawn on-chain. """

    def __init__(self, channel_identifier, unlock_proofs):
        self.channel_identifier = channel_identifier
        self.unlock_proofs = unlock_proofs

    def __str__(self):
        return '<ContractSendChannelWithdraw channel:{} unlock_proofs:{}>'.format(
            pex(self.channel_identifier),
            self.unlock_proofs,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractSendChannelWithdraw) and
            self.channel_identifier == other.channel_identifier and
            self.unlock_proofs == other.unlock_proofs
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class EventTransferSentSuccess(Event):
    """ Event emitted by the initiator when a transfer is considered sucessful.

    A transfer is considered sucessful when the initiator's payee hop sends the
    reveal secret message, assuming that each hop in the mediator chain has
    also learned the secret and unlock/withdraw its token.

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
        Mediators cannot use this event, since an unlock may be locally
        sucessful but there is no knowledge about the global transfer.
    """

    def __init__(self, identifier, amount, target):
        self.identifier = identifier
        self.amount = amount
        self.target = target

    def __eq__(self, other):
        if not isinstance(other, EventTransferSentSuccess):
            return False

        return (
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

    def __eq__(self, other):
        if not isinstance(other, EventTransferSentFailed):
            return False

        return (
            self.identifier == other.identifier and
            self.reason == other.reason
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class EventTransferReceivedSuccess(Event):
    """ Event emitted when a payee has received a payment.

    Note:
        A payee knows if a lock withdraw has failed, but this is not sufficient
        information to deduce when a transfer has failed, because the initiator may
        try again at a different time and/or with different routes, for this reason
        there is no correspoding `EventTransferReceivedFailed`.
    """

    def __init__(self, identifier, amount, initiator):
        self.identifier = identifier
        self.amount = amount
        self.initiator = initiator

    def __eq__(self, other):
        if not isinstance(other, EventTransferReceivedSuccess):
            return False

        return (
            self.identifier == other.identifier and
            self.amount == other.amount and
            self.initiator == other.initiator
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class SendDirectTransfer(Event):
    """ Event emitted when a direct transfer message must be send. """

    def __init__(
            self,
            identifier,
            balance_proof,
            token,
            recipient):

        self.identifier = identifier
        self.balance_proof = balance_proof
        self.token = token
        self.recipient = recipient

    def __str__(self):
        return (
            '<SendDirectTransfer identifier:{} balance_proof:{} token:{} recipient:{}>'
        ).format(
            self.identifier,
            self.balance_proof,
            pex(self.token),
            pex(self.recipient),
        )

    def __eq__(self, other):
        return (
            isinstance(other, SendDirectTransfer) and
            self.identifier == other.identifier and
            self.balance_proof == other.balance_proof and
            self.token == other.token and
            self.recipient == other.recipient
        )

    def __ne__(self, other):
        return not self.__eq__(other)
