# -*- coding: utf8 -*-
from ethereum import slogging

from raiden.messages import (
    DirectTransfer, LockedTransfer, MediatedTransfer, BaseError, Lock, CancelTransfer,
)
from raiden.utils import sha3
from raiden.mtree import merkleroot, get_proof

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


def create_directtransfer(from_, to_, asset_address, amount, secret=None):
    """ Create a transfer for `amount` of `asset_address` between `from_` and `to_`. """
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
        asset=asset_address,
        balance=to_.balance + amount,
        recipient=to_.address,
        locksroot=to_.locked.root,  # not changed
        secret=secret,
    )


def create_lockedtransfer(from_, to_, asset_address, amount, expiration, hashlock):  # pylint: disable=too-many-arguments
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
        asset=asset_address,
        balance=to_.balance,  # not changed
        recipient=to_.address,
        locksroot=updated_locksroot,
        lock=lock,
    )


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

        self.nonce = 0  #: sending nonce
        self.locked = LockedTransfers()  #: locked received

    def distributable(self, other):
        """ Return the available amount of the asset that can be transfer in
        the channel `(total - locked)`.
        """
        return self.balance - other.locked.outstanding

    def claim_locked(self, partner, secret, hashlock=None, locksroot=None):
        """ Update the balance of this end of the channel by claiming the
        transfer.

        Args:
            partner: The partner end from which we are receiving, this is
                required to keep both ends in sync.
            secret: Releases a lock.
            hashlock: The sha3() of the secret, can be given to improve speed
                by avoid recomputing the sha3().

        Raises:
            InvalidSecret: If there is no lock register for the given secret
                (or `hashlock` if given).

        Returns:
            float: The amount that was locked.
        """
        hashlock = hashlock or sha3(secret)

        if hashlock not in self.locked:
            raise InvalidSecret(hashlock)

        lock = self.locked[hashlock].lock

        if locksroot and self.locked.root_with(None, exclude=lock.lock) != locksroot:
            raise InvalidLocksRoot(hashlock)

        amount = lock.amount

        self.balance += amount
        partner.balance -= amount

        self.locked.remove(hashlock)


class Channel(object):
    # pylint: disable=too-many-instance-attributes,too-many-arguments

    def __init__(self, chain, asset_address, channel_address, our_address,
                 our_balance, partner_address, partner_balance):
        self.chain = chain
        self.asset_address = asset_address
        self.channel_address = channel_address

        self.min_locktime = 10  # FIXME
        self.wasclosed = False
        # self.received_transfers = []
        # self.sent_transfers = []
        self.our_state = ChannelEndState(
            our_address,
            our_balance,
        )
        self.partner_state = ChannelEndState(
            partner_address,
            partner_balance,
        )

    @property
    def isopen(self):
        if self.wasclosed:
            return False

        return self.chain.isopen(self.channel_address)

    def register_locked_transfer(self, transfer):
        if transfer.recipient == self.our_state.address:
            self.our_state.locked.add(transfer)
        else:
            assert transfer.recipient == self.partner_state.address
            self.partner_state.locked.add(transfer)

    def claim_locked(self, secret, hashlock=None):
        """ Claim locked transfer from any of the ends of the channel.

        Args:
            secret: Releases a lock.
            hashlock: The sha3() of the secret, can be given to improve speed
                by avoid recomputing the sha3().
        """
        hashlock = hashlock or sha3(secret)

        # sending
        if hashlock in self.our_state.locked:
            self.our_state.claim_locked(self.partner_state, secret, hashlock)

        # receiving
        if hashlock in self.partner_state.locked:
            self.partner_state.claim_locked(self.partner_state, secret, hashlock)

    def register_received_transfer(self, transfer):
        """
        Raises:
            InvalidSecret: If there is no lock register for the given secret.
            InvalidLocksRoot: If locksroot check fails.
            ValueError: If there is an address mismatch (asset or node address).
            InvalidNonce: If the expected nonce does not match.
        """
        if transfer.asset != self.asset_address:
            raise ValueError('Asset address mismatch')

        if transfer.recipient != self.our_state.address:
            raise ValueError('Address mismatch')

        if transfer.nonce != self.partner_state.nonce:
            raise InvalidNonce(transfer)

        # update balance with released lock if secret
        if isinstance(transfer, DirectTransfer) and transfer.secret:
            self.claim_locked(transfer.secret, transfer.locksroot)

        # collect funds
        allowance = transfer.balance - self.our_state.balance
        assert allowance >= 0

        partner_distributable = self.partner_state.distributable(self.our_state)
        if allowance > partner_distributable:
            raise InsufficientBalance(transfer)

        # register locked funds
        if isinstance(transfer, (LockedTransfer, MediatedTransfer, CancelTransfer)):
            assert transfer.lock.amount > 0

            if self.our_state.locked.root_with(transfer.lock) != transfer.locksroot:
                raise InvalidLocksRoot(transfer)

            if allowance + transfer.lock.amount > partner_distributable:
                raise InsufficientBalance(transfer)

            if transfer.lock.expiration - self.min_locktime < self.chain.block_number:
                raise InvalidLockTime(transfer)

            self.register_locked_transfer(transfer)

        # all checks passed
        self.our_state.balance += allowance
        self.partner_state.balance -= allowance
        self.partner_state.nonce += 1
        # self.received_transfers.append(transfer)

    def register_sent_transfer(self, transfer):
        assert transfer.asset == self.asset_address
        assert transfer.recipient == self.partner_state.address
        assert transfer.nonce == self.our_state.nonce

        # update balance with released lock if secret
        if isinstance(transfer, Transfer) and transfer.secret:
            self.claim_locked(transfer.secret, transfer.locksroot)

        # deduct funds
        allowance = transfer.balance - self.partner_state.balance
        assert allowance >= 0

        distributable = self.our_state.distributable(self.partner_state)
        assert allowance <= distributable

        if isinstance(transfer, DirectTransfer) and transfer.secret:
            self.claim_locked(transfer.secret, transfer.locksroot)

        # register locked funds
        if isinstance(transfer, (LockedTransfer, MediatedTransfer)):
            amount = transfer.lock.amount
            distributable = distributable
            expiration = transfer.lock.expiration
            min_locktime = self.min_locktime
            block_number = self.chain.block_number

            log.debug(
                'register_sent_transfer',
                amount=amount,
                allowance=allowance,
                distributable=distributable,
                expiration=expiration,
                min_locktime=min_locktime,
                block_number=block_number,
            )

            assert amount > 0
            assert allowance + amount <= distributable
            assert expiration - min_locktime >= block_number

            # FIXME: check locksroot!!!
            self.register_locked_transfer(transfer)

        # all checks passed
        self.partner_state.balance += allowance
        self.our_state.balance -= allowance
        self.our_state.nonce += 1
        # self.sent_transfers.append(transfer)

    def register_transfer(self, transfer):
        if not transfer.sender:
            raise ValueError('Unsigned transfer')

        if transfer.recipient == self.partner_state.address:
            self.register_sent_transfer(transfer)
        elif transfer.recipient == self.our_state.address:
            self.register_received_transfer(transfer)
        else:
            raise ValueError('Invalid address')

    def create_directtransfer(self, amount, secret=None):
        """ Return a DirectTransfer message, used for transfer that don't need
        to be mediated.
        """
        if not self.isopen:
            raise ValueError('The channel is closed')

        return create_directtransfer(
            self.our_state,
            self.partner_state,
            amount,
            self.asset_address,
            secret,
        )

    def create_lockedtransfer(self, amount, expiration, hashlock):
        if not self.isopen:
            raise ValueError('The channel is closed')

        if expiration < self.chain.block_number:
            raise ValueError('Expiration set to the past')

        return create_lockedtransfer(
            self.our_state,
            self.partner_state,
            amount,
            self.asset_address,
            expiration,
            hashlock,
        )
