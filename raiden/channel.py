# -*- coding: utf8 -*-
from ethereum import slogging

from raiden.messages import DirectTransfer, LockedTransfer, BaseError, Lock
from raiden.mtree import merkleroot, get_proof
from raiden.utils import sha3

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class InvalidNonce(BaseError):
    pass


class InvalidSecret(BaseError):
    pass


class InvalidLocksRoot(BaseError):
    pass


class InvalidLockTime(BaseError):
    pass


class InsufficientBalance(BaseError):
    pass


class LockedTransfers(object):

    def __init__(self):
        self.locked = dict()
        self._cached_lock_hashes = []
        self._cached_root = None

    def add(self, transfer):
        assert transfer.lock.hashlock not in self.locked
        self.locked[transfer.lock.hashlock] = transfer
        self._cached_lock_hashes.append(sha3(transfer.lock.asstring))
        self._cached_root = None

    def remove(self, hashlock):
        self._cached_lock_hashes.remove(sha3(self.get(hashlock).lock.asstring))
        self._cached_root = None
        del self.locked[hashlock]

    def __contains__(self, hashlock):
        return hashlock in self.locked

    def __len__(self):
        return len(self.locked)

    def __getitem__(self, key):
        return self.locked[key]

    get = __getitem__

    @property
    def outstanding(self):
        return sum(
            transfer.lock.amount
            for transfer in self.locked.values()
        )

    @property
    def root(self):
        if not self._cached_root:
            self._cached_root = merkleroot(self._cached_lock_hashes)
        return self._cached_root

    def root_with(self, lock=None, exclude=None):
        assert not lock or isinstance(lock, Lock)
        assert not exclude or isinstance(exclude, Lock)
        lock_hash = exclude_hash = None
        # temporarily add / remove
        if lock:
            lock_hash = sha3(lock.asstring)
            self._cached_lock_hashes.append(lock_hash)
        if exclude:
            exclude_hash = sha3(exclude.asstring)
            self._cached_lock_hashes.remove(exclude_hash)
        # calc
        root = merkleroot(self._cached_lock_hashes)
        # restore
        if lock_hash:
            assert lock_hash in self._cached_lock_hashes
            self._cached_lock_hashes.remove(lock_hash)
        if exclude:
            self._cached_lock_hashes.append(exclude_hash)
        return root

    def get_proof(self, transfer):
        hashlock = transfer.lock.hashlock
        transfer = self.locked[hashlock]
        proof_for = sha3(transfer.lock.asstring)
        proof = get_proof(self._cached_lock_hashes, proof_for)
        return proof


class ChannelEndState(object):
    """ Tracks the state of one of the participants in a channel. """

    def __init__(self, participant_address, participant_balance):
        self.initial_balance = participant_balance  #: initial balance
        self.balance = participant_balance  #: current balance
        self.address = participant_address  #: node's address

        self.nonce = 0  #: sequential nonce, current value has not been used
        self.locked = LockedTransfers()  #: locked received

    def distributable(self, other):
        """ Return the available amount of the asset that can be transfered in
        the channel `(total - locked)`.
        """
        return self.balance - other.locked.outstanding

    def claim_locked(self, partner, secret, locksroot=None):
        """ Update the balance of this end of the channel by claiming the
        transfer.

        Args:
            partner: The partner end from which we are receiving, this is
                required to keep both ends in sync.
            secret: Releases a lock.

        Raises:
            InvalidSecret: If there is no lock register for the given secret
                (or `hashlock` if given).

        Returns:
            float: The amount that was locked.
        """
        hashlock = sha3(secret)

        if hashlock not in self.locked:
            raise InvalidSecret(hashlock)

        lock = self.locked[hashlock].lock

        if locksroot and self.locked.root_with(None, exclude=lock) != locksroot:
            raise InvalidLocksRoot(hashlock)

        amount = lock.amount

        self.balance += amount
        partner.balance -= amount

        self.locked.remove(hashlock)


class Channel(object):
    # pylint: disable=too-many-instance-attributes,too-many-arguments

    def __init__(self, chain, asset_address, nettingcontract_address,
                 our_state, partner_state, min_locktime):
        self.chain = chain
        self.asset_address = asset_address
        self.nettingcontract_address = nettingcontract_address
        self.our_state = our_state
        self.partner_state = partner_state
        self.min_locktime = min_locktime

        self.wasclosed = False
        self.received_transfers = []
        self.sent_transfers = []  #: transfers that were sent, required for settling

    @property
    def isopen(self):
        if self.wasclosed:
            return False

        return self.chain.isopen(self.asset_address, self.nettingcontract_address)

    @property
    def distributable(self):
        """ Return the available amount of the asset that our end of the
        channel can transfer.
        """
        return self.our_state.distributable(self.partner_state)

    def claim_locked(self, secret, locksroot=None):
        """ Claim locked transfer from any of the ends of the channel.

        Args:
            secret: The secret that releases a locked transfer.
        """
        hashlock = sha3(secret)

        # receiving a secret (releasing our funds)
        if hashlock in self.our_state.locked:
            self.our_state.claim_locked(self.partner_state, secret, locksroot)

        # sending a secret (updating the mirror)
        if hashlock in self.partner_state.locked:
            self.partner_state.claim_locked(self.our_state, secret, locksroot)

    def register_transfer(self, transfer):
        """ Register a signed transfer, updating the channel's state accordingly. """

        if transfer.recipient == self.partner_state.address:
            self.register_transfer_from_to(
                transfer,
                from_state=self.our_state,
                to_state=self.partner_state,
            )
            self.sent_transfers.append(transfer)

        elif transfer.recipient == self.our_state.address:
            self.register_transfer_from_to(
                transfer,
                from_state=self.partner_state,
                to_state=self.our_state,
            )
            self.received_transfers.append(transfer)

        else:
            raise ValueError('Invalid address')

    def register_transfer_from_to(self, transfer, from_state, to_state):  # noqa
        """ Validates and register a signed transfer, updating the channel's state accordingly.

        Note:
            The transfer must be register before it is sent, not on
            acknowledgement. That is necessary for to reasons:

            - Guarantee that the transfer is valid.
            - Deduct the balance early avoiding a window of time were the user
                could intentionally or not send a transaction without funds.

        Raises:
            InsufficientBalance: If the transfer is negative or above the distributable amount.
            InvalidLocksRoot: If locksroot check fails.
            InvalidLockTime: If the transfer has expired.
            InvalidNonce: If the expected nonce does not match.
            InvalidSecret: If there is no lock registered for the given secret.
            ValueError: If there is an address mismatch (asset or node address).
        """
        if transfer.asset != self.asset_address:
            raise ValueError('Asset address mismatch')

        if transfer.recipient != to_state.address:
            raise ValueError('Unknow recipient')

        if transfer.sender != from_state.address:
            raise ValueError('Unsigned transfer')

        # nonce is changed only when a transfer is registered, if the test fail
        # either we are out of sync or it's an forged transfer
        if transfer.nonce != from_state.nonce:
            raise InvalidNonce(transfer)

        # transfer.balance has a new balance for the channel participant
        transfer_amount = transfer.balance - to_state.balance
        distributable = from_state.distributable(to_state)

        if transfer_amount < 0:
            raise ValueError('Negative transfer')

        if transfer_amount > distributable:
            raise InsufficientBalance(transfer)

        if isinstance(transfer, LockedTransfer):
            if transfer_amount + transfer.lock.amount > distributable:
                raise InsufficientBalance(transfer)

            if to_state.locked.root_with(transfer.lock) != transfer.locksroot:
                raise InvalidLocksRoot(transfer)

            if transfer.lock.expiration - self.min_locktime < self.chain.block_number:
                raise InvalidLockTime(transfer)

        # all checks need to be done before the internal state of the channel
        # is changed, otherwise if a check fails and state was changed the
        # channel will be left trashed

        if isinstance(transfer, LockedTransfer):
            to_state.locked.add(transfer)

        if isinstance(transfer, DirectTransfer) and transfer.secret:
            to_state.claim_locked(
                from_state,
                transfer.secret,
                transfer.locksroot,
            )

        # all checks passed, update balances
        to_state.balance += transfer_amount
        from_state.balance -= transfer_amount
        from_state.nonce += 1

    def create_directtransfer(self, amount, secret=None):
        """ Return a DirectTransfer message.

        This message needs to be signed and registered with the channel before
        sent.
        """
        if not self.isopen:
            raise ValueError('The channel is closed')

        from_ = self.our_state
        to_ = self.partner_state

        distributable = from_.distributable(to_)

        if amount <= 0 or amount > distributable:
            log.debug(
                'Insufficient funds',
                amount=amount,
                distributable=distributable,
            )
            raise ValueError('Insufficient funds')

        return DirectTransfer(
            nonce=from_.nonce,
            asset=self.asset_address,
            balance=to_.balance + amount,
            recipient=to_.address,
            locksroot=to_.locked.root,  # not changed
            secret=secret,
        )

    def create_lockedtransfer(self, amount, expiration, hashlock):
        """ Return a LockedTransfer message.

        This message needs to be signed and registered with the channel before sent.
        """
        if not self.isopen:
            raise ValueError('The channel is closed')

        if expiration < self.chain.block_number:
            raise ValueError('Expiration set to the past')

        from_ = self.our_state
        to_ = self.partner_state

        distributable = from_.distributable(to_)

        if amount <= 0 or amount > distributable:
            log.debug(
                'Insufficient funds',
                amount=amount,
                distributable=distributable,
            )
            raise ValueError('Insufficient funds')

        lock = Lock(amount, expiration, hashlock)

        updated_locksroot = to_.locked.root_with(lock)

        return LockedTransfer(
            nonce=from_.nonce,
            asset=self.asset_address,
            balance=to_.balance,  # not changed
            recipient=to_.address,
            locksroot=updated_locksroot,
            lock=lock,
        )

    def create_mediatedtransfer(self, transfer_initiator, transfer_target, fee,
                                amount, expiration, hashlock):
        """ Return a MediatedTransfer message.

        This message needs to be signed and registered with the channel before
        sent.

        Args:
            transfer_initiator (address): The node that requested the transfer.
            transfer_target (address): The node that the transfer is destinated to.
            amount (float): How much asset is being transfered.
            expiration (int): The maximum block number until the transfer
                message can be received.
        """

        locked_transfer = self.create_lockedtransfer(
            amount,
            expiration,
            hashlock,
        )

        mediated_transfer = locked_transfer.to_mediatedtransfer(
            transfer_target,
            transfer_initiator,
            fee,
        )
        return mediated_transfer

    def create_canceltransfer_for(self, transfer):
        """ Return a message CancelTransfer for `transfer`. """
        lock = transfer.lock

        if lock.hashlock not in self.our_state.locked:
            raise ValueError('Unknow hashlock')

        locked_transfer = self.create_lockedtransfer(
            lock.amount,
            lock.expiration,
            lock.hashlock,
        )

        cancel_transfer = locked_transfer.to_canceltransfer()

        return cancel_transfer
