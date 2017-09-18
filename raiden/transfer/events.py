# -*- coding: utf-8 -*-
from raiden.transfer.architecture import Event
# pylint: disable=too-many-arguments,too-few-public-methods


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
