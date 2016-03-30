# -*- coding: utf8 -*-
from ethereum import slogging

from raiden.messages import (
    Transfer, LockedTransfer, MediatedTransfer, BaseError, Lock, CancelTransfer
)
from raiden.utils import sha3
from raiden.mtree import merkleroot, get_proof
from raiden.blockchain.net_contract import NettingChannelContract

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

    def get(self, hashlock):
        return self.locked[hashlock]

    def remove(self, hashlock):
        self._cached_lock_hashes.remove(sha3(self.get(hashlock).lock.asstring))
        self._cached_root = None
        del self.locked[hashlock]

    def __contains__(self, hashlock):
        return hashlock in self.locked

    def __len__(self):
        return len(self.locked)

    @property
    def outstanding(self):
        return sum([t.lock.amount for t in self.locked.values()])

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


class Channel(object):

    def __init__(self, raiden, contract):
        # avoid cyclic import
        from raiden.raiden_service import RaidenService
        assert isinstance(raiden, RaidenService)

        assert isinstance(contract, NettingChannelContract)
        self.raiden = raiden
        self.contract = contract

        # setup
        self.address = raiden.address
        self.nonce = 0  # sending nonce
        self.locked = LockedTransfers()  # locked received
        self.transfers = []  # transfers done
        self.balance = self.contract.participants[self.address]['deposit']

        # config
        self.min_locktime = 10  # FIXME

        class Partner(object):

            "class mirroring the properties on the other side of the channel"
            address = [a for a in contract.participants if a != self.address][0]
            nonce = 0
            locked = LockedTransfers()
            transfers = []
            balance = self.contract.participants[address]['deposit']

            @property
            def distributable(me):
                return me.balance - self.locked.outstanding

        self.partner = Partner()
        self.wasclosed = False

    @property
    def isopen(self):
        return not self.wasclosed and self.contract.isopen

    @property
    def distributable(self):
        return self.balance - self.partner.locked.outstanding

    def register_locked_transfer(self, transfer):
        if transfer.recipient == self.address:
            self.locked.add(transfer)
        else:
            assert transfer.recipient == self.partner.address
            self.partner.locked.add(transfer)

    def claim_locked(self, secret, hashlock=None):
        """
        the secret releases a lock
        hashlock can be given to improve speed
        """
        hashlock = hashlock or sha3(secret)

        # receiving
        if hashlock in self.locked:
            amount = self.locked.get(hashlock).lock.amount
            self.balance += amount
            self.partner.balance -= amount
            self.locked.remove(hashlock)

        # sending
        if hashlock in self.partner.locked:
            amount = self.partner.locked.get(hashlock).lock.amount
            self.balance -= amount
            self.partner.balance += amount
            self.partner.locked.remove(hashlock)

    def register_received_transfer(self, transfer):
        assert transfer.asset == self.contract.asset_address
        assert transfer.recipient == self.address
        if transfer.nonce != self.partner.nonce:
            raise InvalidNonce(transfer)

        # update balance with released lock if secret
        if isinstance(transfer, Transfer) and transfer.secret:
            hashlock = sha3(transfer.secret)
            if hashlock not in self.locked:
                raise InvalidSecret(transfer)
            t = self.locked.get(hashlock)
            if self.locked.root_with(None, exclude=t.lock) != transfer.locksroot:
                raise InvalidLocksRoot(transfer)
            self.claim_locked(transfer.secret)

        # collect funds
        allowance = transfer.balance - self.balance
        assert allowance >= 0
        if allowance > self.partner.distributable:
            raise InsufficientBalance(transfer)

        # register locked funds
        if isinstance(transfer, (LockedTransfer, MediatedTransfer, CancelTransfer)):
            assert transfer.lock.amount > 0
            if self.locked.root_with(transfer.lock) != transfer.locksroot:
                raise InvalidLocksRoot(transfer)
            if allowance + transfer.lock.amount > self.partner.distributable:
                raise InsufficientBalance(transfer)
            if transfer.lock.expiration - self.min_locktime < self.raiden.chain.block_number:
                raise InvalidLockTime(transfer)

            self.register_locked_transfer(transfer)

        # all checks passed
        self.balance += allowance
        self.partner.balance -= allowance
        self.partner.transfers.append(transfer)
        self.partner.nonce += 1

    def register_sent_transfer(self, transfer):
        assert transfer.asset == self.contract.asset_address
        assert transfer.recipient == self.partner.address
        assert transfer.nonce == self.nonce

        # update balance with released lock if secret
        if isinstance(transfer, Transfer) and transfer.secret:
            # check locksroot!!!
            self.claim_locked(transfer.secret)

        # deduct funds
        allowance = transfer.balance - self.partner.balance
        assert allowance >= 0
        assert allowance <= self.distributable

        # register locked funds
        if isinstance(transfer, (LockedTransfer, MediatedTransfer)):
            amount = transfer.lock.amount
            distributable = self.distributable
            expiration = transfer.lock.expiration
            min_locktime = self.min_locktime
            block_number = self.raiden.chain.block_number

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
        self.balance -= allowance
        self.partner.balance += allowance
        self.transfers.append(transfer)
        self.nonce += 1

    def register_transfer(self, transfer):
        assert transfer.sender, 'transfer is not signed'

        if transfer.recipient == self.partner.address:
            self.register_sent_transfer(transfer)
        else:
            assert transfer.recipient == self.address
            self.register_received_transfer(transfer)

    def create_transfer(self, amount, secret=None):
        assert self.isopen, 'The channel is closed'

        if amount <= 0 or amount > self.distributable:
            log.debug('Insufficient funds', amount=amount, distributable=self.distributable)
            raise ValueError('Insufficient funds')

        transfer = Transfer(
            nonce=self.nonce,
            asset=self.contract.asset_address,
            balance=self.partner.balance + amount,
            recipient=self.partner.address,
            locksroot=self.partner.locked.root,  # not changed
            secret=secret,
        )

        return transfer

    def create_lockedtransfer(self, amount, expiration, hashlock):
        assert self.isopen, 'The channel is closed'

        if amount <= 0 or amount > self.distributable:
            log.debug('Insufficient funds', amount=amount, distributable=self.distributable)
            raise ValueError('Insufficient funds')

        if expiration < self.raiden.chain.block_number:
            raise ValueError('Expiration set to the past')

        lock = Lock(amount, expiration, hashlock)
        updated_locksroot = self.partner.locked.root_with(lock)

        locked_transfer = LockedTransfer(
            nonce=self.nonce,
            asset=self.contract.asset_address,
            balance=self.partner.balance,  # not changed
            recipient=self.partner.address,
            locksroot=updated_locksroot,
            lock=lock,
        )

        return locked_transfer
