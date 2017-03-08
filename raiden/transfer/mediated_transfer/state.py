# -*- coding: utf-8 -*-
from raiden.transfer.architecture import State
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes


def lockedtransfer_from_message(message):
    """ Create LockedTransferState from a MediatedTransfer message. """
    transfer_state = LockedTransferState(
        identifier=message.identifier,
        amount=message.lock.amount,
        token=message.token,
        initiator=message.initiator,
        target=message.target,
        expiration=message.lock.expiration,
        hashlock=message.lock.hashlock,
        secret=None,
    )

    return transfer_state


class InitiatorState(State):
    """ State of a node initiating a mediated transfer.

    Args:
        our_address (address): This node address.
        transfer (LockedTransferState): The description of the mediated transfer.
        routes (RoutesState): Routes available for this transfer.
        block_number (int): Latest known block number.
        random_generator (generator): A generator that yields valid secrets.
    """
    __slots__ = (
        'our_address',
        'transfer',
        'routes',
        'random_generator',
        'block_number',
        'message',
        'route',
        'secretrequest',
        'revealsecret',
        'canceled_transfers',
    )

    def __init__(self, our_address, transfer, routes, block_number, random_generator):
        self.our_address = our_address
        self.transfer = transfer
        self.routes = routes
        self.block_number = block_number
        self.random_generator = random_generator

        self.message = None  #: current message in-transit
        self.route = None  #: current route being used
        self.secretrequest = None
        self.revealsecret = None
        self.canceled_transfers = list()


class MediatorState(State):
    """ State of a node mediating a transfer.

    Args:
        our_address (address): This node address.
        routes (RoutesState): Routes available for this transfer.
        block_number (int): Latest known block number.
        hashlock (bin): The hashlock used for this transfer.
    """
    __slots__ = (
        'our_address',
        'routes',
        'block_number',
        'hashlock',
        'secret',
        'transfers_pair',
    )

    def __init__(
            self,
            our_address,
            routes,
            block_number,
            hashlock):

        self.our_address = our_address
        self.routes = routes
        self.block_number = block_number

        # for convenience
        self.hashlock = hashlock
        self.secret = None

        # keeping all transfers in a single list byzantine behavior for secret
        # reveal and simplifies secret setting
        self.transfers_pair = list()


class TargetState(State):
    """ State of mediated transfer target.  """
    __slots__ = (
        'our_address',
        'from_route',
        'from_transfer',
        'block_number',
        'secret',
        'state',
    )

    valid_states = (
        'secret_request',
        'reveal_secret',
        'balance_proof',
    )

    def __init__(
            self,
            our_address,
            from_route,
            from_transfer,
            block_number):

        self.our_address = our_address
        self.from_route = from_route
        self.from_transfer = from_transfer
        self.block_number = block_number

        self.state = 'secret_request'


class LockedTransferState(State):
    """ State of a transfer that is time hash locked.

    Args:
        identifier (int): A unique identifer for the transfer.
        amount (int): Amount of `token' being transferred.
        token (address): Token being transferred.
        target (address): Transfer target address.
        expiration (int): The absolute block number that the lock expires.
        hashlock (bin): The hashlock.
        secret (bin): The secret that unlocks the lock, may be None.
    """
    __slots__ = (
        'identifier',
        'amount',
        'token',
        'initiator',
        'target',
        'expiration',
        'hashlock',
        'secret',
    )

    def __init__(
            self,
            identifier,
            amount,
            token,
            initiator,
            target,
            expiration,
            hashlock,
            secret):

        self.identifier = identifier
        self.amount = amount
        self.token = token
        self.initiator = initiator
        self.target = target
        self.expiration = expiration
        self.hashlock = hashlock
        self.secret = secret

    def __str__(self):
        return '<HashTimeLocked id={} amount={} token={} target={} expire={} hashlock={}>'.format(
            self.identifier,
            self.amount,
            self.token,
            self.target,
            self.expiration,
            self.hashlock,
        )

    def almost_equal(self, other):
        """ True if both transfers are for the same mediated transfer. """
        if isinstance(other, LockedTransferState):
            # the only value that may change for each hop is the expiration
            return (
                self.identifier == other.identifier and
                self.amount == other.amount and
                self.token == other.token and
                self.target == other.target and
                self.hashlock == other.hashlock and
                self.secret == other.secret
            )

    def __eq__(self, other):
        if isinstance(other, LockedTransferState):
            return (
                self.almost_equal(other) and
                self.expiration == other.expiration
            )

        return False


class MediationPairState(State):
    """ State for a mediated transfer.

    A mediator will pay payee node knowing that there is a payer node to cover
    the token expenses. This state keeps track of the routes and transfer for
    the payer and payee, and the current state of the payment.
    """
    __slots__ = (
        'payee_route',
        'payee_transfer',
        'payee_state',

        'payer_route',
        'payer_transfer',
        'payer_state',
    )

    # payee_pending:
    #   Initial state.
    #
    # payee_secret_revealed:
    #   The payee is following the raiden protocol and has sent a SecretReveal.
    #
    # payee_refund_withdraw:
    #   The corresponding refund transfer was withdrawn on-chain, the payee has
    #   /not/ withdrawn the lock yet, it only learned the secret through the
    #   blockchain.
    #   Note: This state is reachable only if there is a refund transfer, that
    #   is represented by a different MediationPairState, and the refund
    #   transfer is at 'payer_contract_withdraw'.
    #
    # payee_contract_withdraw:
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
        'payee_refund_withdraw',
        'payee_contract_withdraw',
        'payee_balance_proof',
        'payee_expired',
    )

    valid_payer_states = (
        'payer_pending',
        'payer_secret_revealed',    # SendRevealSecret was sent
        'payer_waiting_close',      # ContractSendChannelClose was sent
        'payer_waiting_withdraw',   # ContractSendWithdraw was sent
        'payer_contract_withdraw',  # ContractReceiveWithdraw for the above send received
        'payer_balance_proof',      # ReceiveBalanceProof was received
        'payer_expired',            # None of the above happened and the lock expired
    )

    def __init__(
            self,
            payer_route,
            payer_transfer,
            payee_route,
            payee_transfer):
        """
        Args:
            payer_route (RouteState): The details of the route with the payer.
            payer_transfer (LockedTransferState): The transfer this node
                *received* that will cover the expenses.

            payee_route (RouteState): The details of the route with the payee.
            payee_transfer (LockedTransferState): The transfer this node *sent*
                that will be withdrawn by the payee.
        """
        self.payer_route = payer_route
        self.payer_transfer = payer_transfer

        self.payee_route = payee_route
        self.payee_transfer = payee_transfer

        # these transfers are settled on different payment channels. These are
        # the states of each mediated transfer in respect to each channel.
        self.payer_state = 'payer_pending'
        self.payee_state = 'payee_pending'
