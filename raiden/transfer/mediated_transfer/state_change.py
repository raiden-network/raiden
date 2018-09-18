# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
from typing import List

from eth_utils import to_canonical_address, to_checksum_address

from raiden.transfer.architecture import StateChange
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.state import BalanceProofSignedState, RouteState
from raiden.utils import pex, sha3, typing
from raiden.utils.serialization import deserialize_bytes, serialize_bytes

# Note: The init states must contain all the required data for trying doing
# useful work, ie. there must /not/ be an event for requesting new data.


class ActionInitInitiator(StateChange):
    """ Initial state of a new mediated transfer.

    Args:
        transfer: A state object containing the transfer details.
        routes: A list of possible routes provided by a routing service.
        secret: The secret that must be used with the transfer.
    """

    def __init__(
            self,
            transfer_description: TransferDescriptionWithSecretState,
            routes: typing.List[RouteState],
    ):
        if not isinstance(transfer_description, TransferDescriptionWithSecretState):
            raise ValueError('transfer must be an TransferDescriptionWithSecretState instance.')

        self.transfer = transfer_description
        self.routes = routes

    def __repr__(self):
        return '<ActionInitInitiator transfer:{}>'.format(
            self.transfer,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionInitInitiator) and
            self.transfer == other.transfer and
            self.routes == other.routes
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'transfer': self.transfer,
            'routes': self.routes,
        }

    @classmethod
    def from_dict(cls, data) -> 'ActionInitInitiator':
        return cls(
            transfer_description=data['transfer'],
            routes=data['routes'],
        )


class ActionInitMediator(StateChange):
    """ Initial state for a new mediator.

    Args:
        routes: A list of possible routes provided by a routing service.
        from_route: The payee route.
        from_transfer: The payee transfer.
    """

    def __init__(
            self,
            routes: typing.List[RouteState],
            from_route: RouteState,
            from_transfer: LockedTransferSignedState,
    ):

        if not isinstance(from_route, RouteState):
            raise ValueError('from_route must be a RouteState instance')

        if not isinstance(from_transfer, LockedTransferSignedState):
            raise ValueError('from_transfer must be a LockedTransferSignedState instance')

        self.routes = routes
        self.from_route = from_route
        self.from_transfer = from_transfer

    def __repr__(self):
        return '<ActionInitMediator from_route:{} from_transfer:{}>'.format(
            self.from_route,
            self.from_transfer,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionInitMediator) and
            self.routes == other.routes and
            self.from_route == other.from_route and
            self.from_transfer == other.from_transfer
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def balance_proof(self):
        return self.from_transfer.balance_proof

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'routes': self.routes,
            'from_route': self.from_route,
            'from_transfer': self.from_transfer,
            'balance_proof': self.balance_proof,
            'balance_hash': serialize_bytes(self.balance_proof.balance_hash),
        }

    @classmethod
    def from_dict(cls, data) -> 'ActionInitMediator':
        return cls(
            routes=data['routes'],
            from_route=data['from_route'],
            from_transfer=data['from_transfer'],
        )


class ActionInitTarget(StateChange):
    """ Initial state for a new target.

    Args:
        route: The payee route.
        transfer: The payee transfer.
    """

    def __init__(
            self,
            route: RouteState,
            transfer: LockedTransferSignedState,
    ):
        if not isinstance(route, RouteState):
            raise ValueError('route must be a RouteState instance')

        if not isinstance(transfer, LockedTransferSignedState):
            raise ValueError('transfer must be a LockedTransferSignedState instance')

        self.route = route
        self.transfer = transfer

    def __repr__(self):
        return '<ActionInitTarget route:{} transfer:{}>'.format(
            self.route,
            self.transfer,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionInitTarget) and
            self.route == other.route and
            self.transfer == other.transfer
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def balance_proof(self):
        return self.transfer.balance_proof

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'route': self.route,
            'transfer': self.transfer,
            'balance_proof': self.balance_proof,
            'balance_hash': serialize_bytes(self.balance_proof.balance_hash),
        }

    @classmethod
    def from_dict(cls, data) -> 'ActionInitTarget':
        return cls(
            route=data['route'],
            transfer=data['transfer'],
        )


class ActionCancelRoute(StateChange):
    """ Cancel the current route.
    Notes:
        Used to cancel a specific route but not the transfer. May be used for
        timeouts.
    """

    def __init__(
            self,
            registry_address: typing.Address,
            channel_identifier: typing.ChannelID,
            routes: typing.List[RouteState],
    ):
        self.registry_address = registry_address
        self.identifier = channel_identifier
        self.routes = routes

    def __repr__(self):
        return '<ActionCancelRoute id:{}>'.format(
            self.identifier,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionCancelRoute) and
            self.registry_address == other.registry_address and
            self.identifier == other.identifier and
            self.routes == other.routes
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'registry_address': to_checksum_address(self.registry_address),
            'identifier': self.identifier,
            'routes': self.routes,
        }

    @classmethod
    def from_dict(cls, data) -> 'ActionInitTarget':
        return cls(
            registry_address=to_canonical_address(data['registry_address']),
            channel_identifier=data['identifier'],
            routes=data['routes'],
        )


class ReceiveLockExpired(StateChange):
    """ A LockExpired message received. """

    def __init__(
            self,
            sender: typing.Address,
            balance_proof: BalanceProofSignedState,
            secrethash: typing.SecretHash,
            message_identifier: typing.MessageID,
    ):
        self.sender = sender
        self.balance_proof = balance_proof
        self.secrethash = secrethash
        self.message_identifier = message_identifier

    def __repr__(self):
        return '<ReceiveLockExpired sender:{} balance_proof:{}>'.format(
            pex(self.sender),
            self.balance_proof,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ReceiveLockExpired) and
            self.sender == other.sender and
            self.balance_proof == other.balance_proof and
            self.secrethash == other.secrethash and
            self.message_identifier == other.message_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'sender': to_checksum_address(self.sender),
            'balance_proof': self.balance_proof,
            'balance_hash': serialize_bytes(self.balance_proof.balance_hash),
            'secrethash': serialize_bytes(self.secrethash),
            'message_identifier': self.message_identifier,
        }

    @classmethod
    def from_dict(cls, data) -> 'ReceiveLockExpired':
        return cls(
            sender=to_canonical_address(data['sender']),
            balance_proof=data['balance_proof'],
            secrethash=deserialize_bytes(data['secrethash']),
            message_identifier=data['message_identifier'],
        )


class ReceiveSecretRequest(StateChange):
    """ A SecretRequest message received. """

    def __init__(
            self,
            payment_identifier: typing.PaymentID,
            amount: typing.PaymentAmount,
            expiration: typing.BlockExpiration,
            secrethash: typing.SecretHash,
            sender: typing.Address,
    ):
        self.payment_identifier = payment_identifier
        self.amount = amount
        self.expiration = expiration
        self.secrethash = secrethash
        self.sender = sender
        self.revealsecret = None

    def __repr__(self):
        return '<ReceiveSecretRequest paymentid:{} amount:{} secrethash:{} sender:{}>'.format(
            self.payment_identifier,
            self.amount,
            pex(self.secrethash),
            pex(self.sender),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ReceiveSecretRequest) and
            self.payment_identifier == other.payment_identifier and
            self.amount == other.amount and
            self.secrethash == other.secrethash and
            self.sender == other.sender and
            self.revealsecret == other.revealsecret
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'payment_identifier': self.payment_identifier,
            'amount': self.amount,
            'expiration': self.expiration,
            'secrethash': serialize_bytes(self.secrethash),
            'sender': to_checksum_address(self.sender),
            'revealsecret': self.revealsecret,
        }

    @classmethod
    def from_dict(cls, data) -> 'ReceiveSecretRequest':
        instance = cls(
            payment_identifier=data['payment_identifier'],
            amount=data['amount'],
            expiration=data['expiration'],
            secrethash=deserialize_bytes(data['secrethash']),
            sender=to_canonical_address(data['sender']),
        )
        instance.revealsecret = data['revealsecret']
        return instance


class ReceiveSecretReveal(StateChange):
    """ A SecretReveal message received. """

    def __init__(
            self,
            secret: typing.Secret,
            sender: typing.Address,
    ):
        secrethash = sha3(secret)

        self.secret = secret
        self.secrethash = secrethash
        self.sender = sender

    def __repr__(self):
        return '<ReceiveSecretReveal secrethash:{} sender:{}>'.format(
            pex(self.secrethash),
            pex(self.sender),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ReceiveSecretReveal) and
            self.secret == other.secret and
            self.secrethash == other.secrethash and
            self.sender == other.sender
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'secret': serialize_bytes(self.secret),
            'secrethash': serialize_bytes(self.secrethash),
            'sender': to_checksum_address(self.sender),
        }

    @classmethod
    def from_dict(cls, data) -> 'ReceiveSecretReveal':
        instance = cls(
            secret=deserialize_bytes(data['secret']),
            sender=to_canonical_address(data['sender']),
        )
        instance.secrethash = deserialize_bytes(data['secrethash'])
        return instance


class ReceiveTransferRefundCancelRoute(StateChange):
    """ A RefundTransfer message received by the initiator will cancel the current
    route.
    """

    def __init__(
            self,
            sender: typing.Address,
            routes: typing.List[RouteState],
            transfer: LockedTransferSignedState,
            secret: typing.Secret,
    ):
        if not isinstance(transfer, LockedTransferSignedState):
            raise ValueError('transfer must be an instance of LockedTransferSignedState')

        secrethash = sha3(secret)

        self.sender = sender
        self.transfer = transfer
        self.routes = routes
        self.secrethash = secrethash
        self.secret = secret

    def __repr__(self):
        return '<ReceiveTransferRefundCancelRoute sender:{} transfer:{}>'.format(
            pex(self.sender),
            self.transfer,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ReceiveTransferRefundCancelRoute) and
            self.sender == other.sender and
            self.transfer == other.transfer and
            self.routes == other.routes and
            self.secret == other.secret and
            self.secrethash == other.secrethash
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'secret': serialize_bytes(self.secret),
            'sender': to_checksum_address(self.sender),
            'routes': self.routes,
            'transfer': self.transfer,
        }

    @classmethod
    def from_dict(cls, data) -> 'ReceiveTransferRefundCancelRoute':
        instance = cls(
            sender=to_canonical_address(data['sender']),
            routes=data['routes'],
            transfer=data['transfer'],
            secret=deserialize_bytes(data['secret']),
        )
        return instance


class ReceiveTransferRefund(StateChange):
    """ A RefundTransfer message received. """

    def __init__(
            self,
            sender: typing.Address,
            transfer: LockedTransferSignedState,
            routes: List[RouteState],
    ):
        if not isinstance(transfer, LockedTransferSignedState):
            raise ValueError('transfer must be an instance of LockedTransferSignedState')

        self.sender = sender
        self.transfer = transfer
        self.routes = routes

    def __repr__(self):
        return '<ReceiveTransferRefund sender:{} transfer:{}>'.format(
            pex(self.sender),
            self.transfer,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ReceiveTransferRefund) and
            self.sender == other.sender and
            self.transfer == other.transfer and
            self.routes == other.routes
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'sender': to_checksum_address(self.sender),
            'routes': self.routes,
            'transfer': self.transfer,
        }

    @classmethod
    def from_dict(cls, data) -> 'ReceiveTransferRefund':
        instance = cls(
            sender=to_canonical_address(data['sender']),
            routes=data['routes'],
            transfer=data['transfer'],
        )
        return instance
