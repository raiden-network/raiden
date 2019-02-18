# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
from typing import TYPE_CHECKING

from eth_utils import encode_hex, to_canonical_address, to_checksum_address

from raiden.constants import EMPTY_MERKLE_ROOT
from raiden.transfer.architecture import State
from raiden.transfer.state import (
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    HashTimeLockState,
    RouteState,
    balanceproof_from_envelope,
)
from raiden.utils import pex, serialization, sha3
from raiden.utils.serialization import map_dict
from raiden.utils.typing import (
    Address,
    Any,
    ChannelID,
    Dict,
    InitiatorAddress,
    InitiatorTransfersMap,
    List,
    MessageID,
    Optional,
    PaymentAmount,
    PaymentID,
    PaymentNetworkID,
    Secret,
    SecretHash,
    T_Address,
    TargetAddress,
    TokenAddress,
    TokenNetworkID,
)

# Upgrade pyflakes to 2.0.0 and remove the 'if' and '# noqa'.
if TYPE_CHECKING:
    from raiden.transfer.mediated_transfer.events import SendSecretReveal  # noqa: F401


def lockedtransfersigned_from_message(message):
    """ Create LockedTransferSignedState from a LockedTransfer message. """
    balance_proof = balanceproof_from_envelope(message)

    lock = HashTimeLockState(
        message.lock.amount,
        message.lock.expiration,
        message.lock.secrethash,
    )

    transfer_state = LockedTransferSignedState(
        message.message_identifier,
        message.payment_identifier,
        message.token,
        balance_proof,
        lock,
        message.initiator,
        message.target,
    )

    return transfer_state


class InitiatorPaymentState(State):
    """ State of a payment for the initiator node.
    A single payment may have multiple transfers. E.g. because if one of the
    transfers fails or timeouts another transfer will be started with a
    different secrethash.
    """
    __slots__ = (
        'cancelled_channels',
        'initiator_transfers',
    )

    def __init__(self, initiator_transfers: InitiatorTransfersMap):
        self.initiator_transfers = initiator_transfers
        self.cancelled_channels = list()

    def __repr__(self):
        return '<InitiatorPaymentState transfers:{}>'.format(
            self.initiator_transfers,
        )

    def __eq__(self, other):
        return (
            isinstance(other, InitiatorPaymentState) and
            self.initiator_transfers == other.initiator_transfers and
            self.cancelled_channels == other.cancelled_channels
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'initiator_transfers': map_dict(
                serialization.serialize_bytes,
                serialization.identity,
                self.initiator_transfers,
            ),
            'cancelled_channels': self.cancelled_channels,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'InitiatorPaymentState':
        restored = cls(
            initiator_transfers=map_dict(
                serialization.deserialize_bytes,
                serialization.identity,
                data['initiator_transfers'],
            ),
        )
        restored.cancelled_channels = data['cancelled_channels']

        return restored


class InitiatorTransferState(State):
    """ State of a transfer for the initiator node. """

    __slots__ = (
        'transfer_description',
        'channel_identifier',
        'transfer',
        'revealsecret',
        'received_secret_request',
        'transfer_state',
    )

    valid_transfer_states = (
        'transfer_pending',
        'transfer_cancelled',
    )

    def __init__(
            self,
            transfer_description: 'TransferDescriptionWithSecretState',
            channel_identifier: ChannelID,
            transfer: 'LockedTransferUnsignedState',
            revealsecret: Optional['SendSecretReveal'],
            received_secret_request: bool = False,
    ):

        if not isinstance(transfer_description, TransferDescriptionWithSecretState):
            raise ValueError(
                'transfer_description must be an instance of TransferDescriptionWithSecretState',
            )

        # This is the users description of the transfer. It does not contain a
        # balance proof and it's not related to any channel.
        self.transfer_description = transfer_description

        # This is the channel used to satisfy the above transfer.
        self.channel_identifier = channel_identifier
        self.transfer = transfer
        self.revealsecret = revealsecret
        self.received_secret_request = received_secret_request
        self.transfer_state = 'transfer_pending'

    def __repr__(self):
        return '<InitiatorTransferState transfer:{} channel:{} state:{}>'.format(
            self.transfer,
            self.channel_identifier,
            self.transfer_state,
        )

    def __eq__(self, other):
        return (
            isinstance(other, InitiatorTransferState) and
            self.transfer_description == other.transfer_description and
            self.channel_identifier == other.channel_identifier and
            self.transfer == other.transfer and
            self.revealsecret == other.revealsecret and
            self.received_secret_request == other.received_secret_request and
            self.transfer_state == other.transfer_state
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'transfer_description': self.transfer_description,
            'channel_identifier': str(self.channel_identifier),
            'transfer': self.transfer,
            'revealsecret': self.revealsecret,
            'received_secret_request': self.received_secret_request,
            'transfer_state': self.transfer_state,
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'InitiatorTransferState':
        restored = cls(
            transfer_description=data['transfer_description'],
            channel_identifier=ChannelID(int(data['channel_identifier'])),
            transfer=data['transfer'],
            revealsecret=data['revealsecret'],
            received_secret_request=data['received_secret_request'],
        )
        restored.transfer_state = data['transfer_state']

        return restored


class WaitingTransferState(State):
    def __init__(
            self,
            transfer: 'LockedTransferSignedState',
            state: str = 'waiting',
    ):
        self.transfer = transfer
        self.state = state

    def __repr__(self):
        return f'<WaitingTransferState state:{self.state} transfer:{self.transfer}>'

    def __eq__(self, other):
        return (
            isinstance(other, WaitingTransferState) and
            self.transfer == other.transfer and
            self.state == other.state
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'state': self.state,
            'transfer': self.transfer,
        }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WaitingTransferState':
        restored = cls(
            transfer=data['transfer'],
            state=data['state'],
        )

        return restored


class MediatorTransferState(State):
    """ State of a transfer for the mediator node.
    A mediator may manage multiple channels because of refunds, but all these
    channels will be used for the same transfer (not for different payments).
    Args:
        secrethash: The secrethash used for this transfer.
    """

    __slots__ = (
        'secrethash',
        'secret',
        'transfers_pair',
        'waiting_transfer',
        'routes',
    )

    def __init__(
            self,
            secrethash: SecretHash,
            routes: List[RouteState],
    ):
        self.secrethash = secrethash
        self.secret: Secret = None
        self.transfers_pair: List[MediationPairState] = list()
        self.waiting_transfer: WaitingTransferState = None
        self.routes = routes

    def __repr__(self):
        return '<MediatorTransferState secrethash:{} qtd_transfers:{}>'.format(
            pex(self.secrethash),
            len(self.transfers_pair),
        )

    def __eq__(self, other):
        return (
            isinstance(other, MediatorTransferState) and
            self.secrethash == other.secrethash and
            self.secret == other.secret and
            self.transfers_pair == other.transfers_pair and
            self.waiting_transfer == other.waiting_transfer and
            self.routes == other.routes
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'secrethash': serialization.serialize_bytes(self.secrethash),
            'transfers_pair': self.transfers_pair,
            'waiting_transfer': self.waiting_transfer,
            'routes': self.routes,
        }

        if self.secret is not None:
            result['secret'] = serialization.serialize_bytes(self.secret)

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MediatorTransferState':
        restored = cls(
            secrethash=serialization.deserialize_bytes(data['secrethash']),
            routes=data['routes'],
        )
        restored.transfers_pair = data['transfers_pair']
        restored.waiting_transfer = data['waiting_transfer']

        secret = data.get('secret')
        if secret is not None:
            restored.secret = serialization.deserialize_bytes(secret)

        return restored


class TargetTransferState(State):
    """ State of a transfer for the target node. """

    __slots__ = (
        'route',
        'transfer',
        'secret',
        'state',
    )

    EXPIRED = 'expired'
    OFFCHAIN_SECRET_REVEAL = 'reveal_secret'
    ONCHAIN_SECRET_REVEAL = 'onchain_secret_reveal'
    ONCHAIN_UNLOCK = 'onchain_unlock'
    SECRET_REQUEST = 'secret_request'

    valid_states = (
        EXPIRED,
        OFFCHAIN_SECRET_REVEAL,
        ONCHAIN_SECRET_REVEAL,
        ONCHAIN_UNLOCK,
        SECRET_REQUEST,
    )

    def __init__(
            self,
            route: RouteState,
            transfer: 'LockedTransferSignedState',
            secret: Secret = None,
    ):
        self.route = route
        self.transfer = transfer

        self.secret = secret
        self.state = 'secret_request'

    def __repr__(self):
        return '<TargetTransferState transfer:{} state:{}>'.format(
            self.transfer,
            self.state,
        )

    def __eq__(self, other):
        return (
            isinstance(other, TargetTransferState) and
            self.route == other.route and
            self.transfer == other.transfer and
            self.secret == other.secret and
            self.state == other.state
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'route': self.route,
            'transfer': self.transfer,
            'state': self.state,
        }

        if self.secret is not None:
            result['secret'] = serialization.serialize_bytes(self.secret)

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TargetTransferState':
        restored = cls(
            route=data['route'],
            transfer=data['transfer'],
        )
        restored.state = data['state']

        secret = data.get('secret')
        if secret is not None:
            restored.secret = serialization.deserialize_bytes(secret)

        return restored


class LockedTransferState(State):
    pass


class LockedTransferUnsignedState(LockedTransferState):
    """ State for a transfer created by the local node which contains a hash
    time lock and may be sent.
    """

    __slots__ = (
        'payment_identifier',
        'token',
        'balance_proof',
        'lock',
        'initiator',
        'target',
    )

    def __init__(
            self,
            payment_identifier: PaymentID,
            token: TokenAddress,
            balance_proof: BalanceProofUnsignedState,
            lock: HashTimeLockState,
            initiator: Address,
            target: Address,
    ):
        if not isinstance(lock, HashTimeLockState):
            raise ValueError('lock must be a HashTimeLockState instance')

        if not isinstance(balance_proof, BalanceProofUnsignedState):
            raise ValueError('balance_proof must be a BalanceProofUnsignedState instance')

        # At least the lock for this transfer must be in the locksroot, so it
        # must not be empty
        if balance_proof.locksroot == EMPTY_MERKLE_ROOT:
            raise ValueError('balance_proof must not be empty')

        self.payment_identifier = payment_identifier
        self.token = token
        self.balance_proof = balance_proof
        self.lock = lock
        self.initiator = initiator
        self.target = target

    def __repr__(self):
        return (
            '<'
            'LockedTransferUnsignedState id:{} token:{} balance_proof:{} '
            'lock:{} target:{}'
            '>'
        ).format(
            self.payment_identifier,
            encode_hex(self.token),
            self.balance_proof,
            self.lock,
            encode_hex(self.target),
        )

    def __eq__(self, other):
        return (
            isinstance(other, LockedTransferUnsignedState) and
            self.payment_identifier == other.payment_identifier and
            self.token == other.token and
            self.balance_proof == other.balance_proof and
            self.lock == other.lock and
            self.initiator == other.initiator and
            self.target == other.target
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'payment_identifier': str(self.payment_identifier),
            'token': to_checksum_address(self.token),
            'balance_proof': self.balance_proof,
            'lock': self.lock,
            'initiator': to_checksum_address(self.initiator),
            'target': to_checksum_address(self.target),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LockedTransferUnsignedState':
        restored = cls(
            payment_identifier=int(data['payment_identifier']),
            token=to_canonical_address(data['token']),
            balance_proof=data['balance_proof'],
            lock=data['lock'],
            initiator=to_canonical_address(data['initiator']),
            target=to_canonical_address(data['target']),
        )

        return restored


class LockedTransferSignedState(LockedTransferState):
    """ State for a received transfer which contains a hash time lock and a
    signed balance proof.
    """

    __slots__ = (
        'message_identifier',
        'payment_identifier',
        'token',
        'balance_proof',
        'lock',
        'initiator',
        'target',
    )

    def __init__(
            self,
            message_identifier: MessageID,
            payment_identifier: PaymentID,
            token: Address,
            balance_proof: BalanceProofSignedState,
            lock: HashTimeLockState,
            initiator: InitiatorAddress,
            target: TargetAddress,
    ):
        if not isinstance(lock, HashTimeLockState):
            raise ValueError('lock must be a HashTimeLockState instance')

        if not isinstance(balance_proof, BalanceProofSignedState):
            raise ValueError('balance_proof must be a BalanceProofSignedState instance')

        # At least the lock for this transfer must be in the locksroot, so it
        # must not be empty
        if balance_proof.locksroot == EMPTY_MERKLE_ROOT:
            raise ValueError('balance_proof must not be empty')

        self.message_identifier = message_identifier
        self.payment_identifier = payment_identifier
        self.token = token
        self.balance_proof = balance_proof
        self.lock = lock
        self.initiator = initiator
        self.target = target

    def __repr__(self):
        return (
            '<'
            'LockedTransferSignedState msgid:{} id:{} token:{} lock:{}'
            ' target:{}'
            '>'
        ).format(
            self.message_identifier,
            self.payment_identifier,
            encode_hex(self.token),
            self.lock,
            encode_hex(self.target),
        )

    @property
    def payer_address(self):
        return self.balance_proof.sender

    def __eq__(self, other):
        return (
            isinstance(other, LockedTransferSignedState) and
            self.message_identifier == other.message_identifier and
            self.payment_identifier == other.payment_identifier and
            self.token == other.token and
            self.balance_proof == other.balance_proof and
            self.lock == other.lock and
            self.initiator == other.initiator and
            self.target == other.target
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'message_identifier': str(self.message_identifier),
            'payment_identifier': str(self.payment_identifier),
            'token': to_checksum_address(self.token),
            'balance_proof': self.balance_proof,
            'lock': self.lock,
            'initiator': to_checksum_address(self.initiator),
            'target': to_checksum_address(self.target),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LockedTransferSignedState':
        restored = cls(
            message_identifier=int(data['message_identifier']),
            payment_identifier=int(data['payment_identifier']),
            token=to_canonical_address(data['token']),
            balance_proof=data['balance_proof'],
            lock=data['lock'],
            initiator=to_canonical_address(data['initiator']),
            target=to_canonical_address(data['target']),
        )

        return restored


class TransferDescriptionWithSecretState(State):
    """ Describes a transfer (target, amount, and token) and contains an
    additional secret that can be used with a hash-time-lock.
    """

    __slots__ = (
        'payment_network_identifier',
        'payment_identifier',
        'amount',
        'token_network_identifier',
        'initiator',
        'target',
        'secret',
        'secrethash',
    )

    def __init__(
            self,
            payment_network_identifier: PaymentNetworkID,
            payment_identifier: PaymentID,
            amount: PaymentAmount,
            token_network_identifier: TokenNetworkID,
            initiator: InitiatorAddress,
            target: TargetAddress,
            secret: Secret,
    ):
        secrethash = sha3(secret)

        self.payment_network_identifier = payment_network_identifier
        self.payment_identifier = payment_identifier
        self.amount = amount
        self.token_network_identifier = token_network_identifier
        self.initiator = initiator
        self.target = target
        self.secret = secret
        self.secrethash = secrethash

    def __repr__(self):
        return (
            '<'
            'TransferDescriptionWithSecretState token_network:{} amount:{} target:{} secrethash:{}'
            '>'
        ).format(
            pex(self.token_network_identifier),
            self.amount,
            pex(self.target),
            pex(self.secrethash),
        )

    def __eq__(self, other):
        return (
            isinstance(other, TransferDescriptionWithSecretState) and
            self.payment_network_identifier == other.payment_network_identifier and
            self.payment_identifier == other.payment_identifier and
            self.amount == other.amount and
            self.token_network_identifier == other.token_network_identifier and
            self.initiator == other.initiator and
            self.target == other.target and
            self.secret == other.secret and
            self.secrethash == other.secrethash
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'payment_network_identifier': to_checksum_address(self.payment_network_identifier),
            'payment_identifier': str(self.payment_identifier),
            'amount': str(self.amount),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'initiator': to_checksum_address(self.initiator),
            'target': to_checksum_address(self.target),
            'secret': serialization.serialize_bytes(self.secret),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TransferDescriptionWithSecretState':
        restored = cls(
            payment_network_identifier=to_canonical_address(data['payment_network_identifier']),
            payment_identifier=int(data['payment_identifier']),
            amount=int(data['amount']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            initiator=to_canonical_address(data['initiator']),
            target=to_canonical_address(data['target']),
            secret=serialization.deserialize_bytes(data['secret']),
        )

        return restored


class MediationPairState(State):
    """ State for a mediated transfer.
    A mediator will pay payee node knowing that there is a payer node to cover
    the token expenses. This state keeps track of the routes and transfer for
    the payer and payee, and the current state of the payment.
    """

    __slots__ = (
        'payee_address',
        'payee_transfer',
        'payee_state',
        'payer_transfer',
        'payer_state',
    )

    # payee_pending:
    #   Initial state.
    #
    # payee_secret_revealed:
    #   The payee is following the raiden protocol and has sent a SecretReveal.
    #
    # payee_contract_unlock:
    #   The payee received the token on-chain. A transition to this state is
    #   valid from all but the `payee_expired` state.
    #
    # payee_balance_proof:
    #   This node has sent a SendBalanceProof to the payee with the balance
    #   updated.
    #
    # payee_expired:
    #   The lock has expired.
    valid_payee_states = (
        'payee_pending',
        'payee_secret_revealed',
        'payee_contract_unlock',
        'payee_balance_proof',
        'payee_expired',
    )

    valid_payer_states = (
        'payer_pending',
        'payer_secret_revealed',        # SendSecretReveal was sent
        'payer_waiting_unlock',         # ContractSendChannelBatchUnlock was sent
        'payer_waiting_secret_reveal',  # ContractSendSecretReveal was sent
        'payer_balance_proof',          # ReceiveUnlock was received
        'payer_expired',                # None of the above happened and the lock expired
    )

    def __init__(
            self,
            payer_transfer: LockedTransferSignedState,
            payee_address: Address,
            payee_transfer: LockedTransferUnsignedState,
    ):
        if not isinstance(payer_transfer, LockedTransferSignedState):
            raise ValueError('payer_transfer must be a LockedTransferSignedState instance')

        if not isinstance(payee_address, T_Address):
            raise ValueError('payee_address must be an address')

        if not isinstance(payee_transfer, LockedTransferUnsignedState):
            raise ValueError('payee_transfer must be a LockedTransferUnsignedState instance')

        self.payer_transfer = payer_transfer
        self.payee_address = payee_address
        self.payee_transfer = payee_transfer

        # these transfers are settled on different payment channels. These are
        # the states of each mediated transfer in respect to each channel.
        self.payer_state = 'payer_pending'
        self.payee_state = 'payee_pending'

    def __repr__(self):
        return '<MediationPairState payee_address:{} payee_transfer:{} payer_transfer{}>'.format(
            pex(self.payee_address),
            self.payer_transfer,
            self.payee_transfer,
        )

    @property
    def payer_address(self):
        return self.payer_transfer.payer_address

    def __eq__(self, other):
        return (
            isinstance(other, MediationPairState) and
            self.payee_address == other.payee_address and
            self.payee_transfer == other.payee_transfer and
            self.payee_state == other.payee_state and
            self.payer_transfer == other.payer_transfer and
            self.payer_state == other.payer_state
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'payee_address': to_checksum_address(self.payee_address),
            'payee_transfer': self.payee_transfer,
            'payee_state': self.payee_state,
            'payer_transfer': self.payer_transfer,
            'payer_state': self.payer_state,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MediationPairState':
        restored = cls(
            payer_transfer=data['payer_transfer'],
            payee_address=to_canonical_address(data['payee_address']),
            payee_transfer=data['payee_transfer'],
        )
        restored.payer_state = data['payer_state']
        restored.payee_state = data['payee_state']

        return restored
