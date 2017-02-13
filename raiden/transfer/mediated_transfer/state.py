# -*- coding: utf-8 -*-
from raiden.transfer.architecture import State
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes


class InitiatorState(State):
    """ State of a node initiating a mediated transfer.

    Args:
        our_address (address): This node address.
        transfer (TransferState): The description of the mediated transfer.
        routes (RoutesState): Routes available for this transfer.
        block_number (int): Latest known block number.
        random_generator (generator): A generator that yields valid secrets.
    """
    def __init__(self, our_address, transfer, routes, block_number, random_generator):
        self.our_address = our_address
        self.transfer = transfer
        self.routes = routes
        self.random_generator = random_generator
        self.block_number = block_number

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
    def __init__(self,
                 our_address,
                 routes,
                 block_number,
                 hashlock):

        self.our_address = our_address
        self.routes = routes
        self.block_number = block_number
        self.hashlock = hashlock  # for convenience

        self.secret = None
        self.route = None  #: current route being used

        # keeping all transfers in a single list byzantine behavior for secret
        # reveal and simplifies secret setting
        self.transfers_pair = list()


class TargetState(State):
    """ State of mediated transfer target.  """
    def __init__(self,
                 our_address,
                 from_route,
                 from_transfer,
                 hashlock,
                 block_number):

        self.our_address = our_address
        self.from_route = from_route
        self.from_transfer = from_transfer
        self.hashlock = hashlock
        self.block_number = block_number

        self.secret = None


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
    def __init__(self,
                 identifier,
                 amount,
                 token,
                 target,
                 expiration,
                 hashlock,
                 secret):

        self.identifier = identifier
        self.amount = amount
        self.token = token
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

    def __eq__(self, other):
        if isinstance(other, LockedTransferState):
            return (
                self.identifier == other.identifier and
                self.amount == other.amount and
                self.token == other.token and
                self.target == other.target and
                self.expiration == other.expiration and
                self.hashlock == other.hashlock and
                self.secret == other.secret
            )

        return False


class MediationPairState(State):
    """ State for a mediated transfer.

    A mediator will pay payee node knowing that there is a payer node to cover
    the token expenses. This state keeps track of the routes and transfer for
    the payer and payee, and the current state of the payment.
    """

    valid_payee_states = (
        'payee_pending',
        'payee_secret_revealed',  # reached on a ReceiveSecretReveal
        'payee_contract_withdraw',  # reached when the /partner/ node unlocks
        'payee_balance_proof',  # reached when this node sends SendBalanceProof
        'payee_expired',
    )

    valid_payer_states = (
        'payer_pending',
        'payer_secret_revealed',  # reached on a SendRevealSecret
        'payer_waiting_withdraw',  # reached when unlock is called
        'payer_contract_withdraw',  # this state is reached the unlock from /this/ node completes
        'payer_balance_proof',  # reached on a ReceiveBalanceProof
        'payer_expired',
    )

    def __init__(self,
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
        self.payer_state = 'payer_pending'

        self.payee_route = payee_route
        self.payee_transfer = payee_transfer
        self.payee_state = 'payee_pending'
