from contracts import NettingChannelContract
import raiden_service
from messages import Transfer, LockedTransfer, MediatedTransfer, BaseError, Lock
from utils import ishash, isaddress, sha3
from mtree import merkleroot, check_proof


class InvalidNonce(BaseError):
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
        r = merkleroot(self._cached_lock_hashes)
        # restore
        if lock_hash:
            assert lock_hash in self._cached_lock_hashes
            self._cached_lock_hashes.remove(lock_hash)
        if exclude:
            self._cached_lock_hashes.append(exclude_hash)
        return r


class Channel(object):

    def __init__(self, raiden, contract):
        assert isinstance(raiden, raiden_service.RaidenService)
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

    def claim_locked(self, secret):
        """
        the secret releases a lock
        """
        hashlock = sha3(secret)
        if hashlock in self.locked:
            amount = self.locked.get(hashlock).lock.amount
            self.balance += amount
            self.partner.balance += amount
            self.locked.remove(hashlock)
        if hashlock in self.partner.locked:
            amount = self.partner.locked.get(hashlock).lock.amount
            self.balance -= amount
            self.partner.balance += amount
            self.partner.locked.remove(hashlock)

    def receive(self, transfer):
        assert transfer.asset == self.contract.asset_address
        assert transfer.recipient == self.address
        if transfer.nonce != self.partner.nonce:
            raise InvalidNonce()

        # update balance with released lock if secret
        if isinstance(transfer, Transfer) and transfer.secret:
            self.claim_locked(transfer.secret)

        # collect funds
        allowance = transfer.balance - self.balance
        assert allowance >= 0
        if allowance > self.partner.distributable:
            raise InsufficientBalance()

        # register locked funds
        if isinstance(transfer, (LockedTransfer, MediatedTransfer)):
            assert transfer.lock.amount > 0
            if allowance + transfer.lock.amount > self.partner.distributable:
                raise InsufficientBalance()
            if transfer.lock.expiration - self.min_locktime < self.raiden.chain.block_number:
                raise InvalidLockTime()

            self.register_locked_transfer(transfer)

        # all checks passed
        self.balance += allowance
        self.partner.balance -= allowance
        self.partner.transfers.append(transfer)
        self.partner.nonce += 1

    def send(self, transfer):
        assert transfer.asset == self.contract.asset_address
        assert transfer.recipient == self.partner.address
        assert transfer.nonce == self.nonce

        # update balance with released lock if secret
        if isinstance(transfer, Transfer) and transfer.secret:
            self.claim_locked(transfer.secret)

        # dedcuct funds
        allowance = transfer.balance - self.partner.balance
        assert allowance >= 0
        assert allowance <= self.distributable

        # register locked funds
        if isinstance(transfer, (LockedTransfer, MediatedTransfer)):
            assert transfer.lock.amount > 0
            assert allowance + transfer.lock.amount <= self.distributable
            assert transfer.lock.expiration - self.min_locktime >= self.raiden.chain.block_number
            self.register_locked_transfer(transfer)

        # all checks passed
        self.balance -= allowance
        self.partner.balance += allowance
        self.transfers.append(transfer)
        self.nonce += 1

    def create_transfer(self, amount, secret=None):
        assert amount >= 0
        assert self.distributable > amount
        assert self.isopen
        t = Transfer(nonce=self.nonce,
                     asset=self.contract.asset_address,
                     balance=self.partner.balance + amount,
                     recipient=self.partner.address,
                     locksroot=self.partner.locked.root,  # not changed
                     secret=secret)
        return t

    def create_locked_transfer(self, amount, expiration, hashlock):
        assert self.distributable > amount, 'insufficient funds'
        assert self.isopen
        assert expiration > self.contract.chain.block_number

        l = Lock(amount, expiration, hashlock)
        updated_locksroot = self.partner.locked.root_with(l)
        t = LockedTransfer(nonce=self.nonce,
                           asset=self.contract.asset_address,
                           balance=self.partner.balance,  # not changed
                           recipient=self.partner.address,
                           locksroot=updated_locksroot,
                           lock=l)
        return t

    def close(self):
        pass
