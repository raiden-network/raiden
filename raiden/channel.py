from contracts import SettlementChannel
from raiden_service import RaidenService
from messages import Transfer, LockedTransfer, MediatedTransfer, BaseError, Lock
from utils import ishash, isaddress, sha3
from mtree import merkleroot, check_proof


class InvalidNonce(BaseError):
    pass


class InsufficientBalance(BaseError):
    pass


class Channel(object):

    def __init__(self, raiden, contract):
        assert isinstance(raiden, RaidenService)
        assert isinstance(contract, SettlementChannel)
        self.raiden = raiden
        self.contract = contract

        # setup
        self.address = raiden.address
        self.nonce = 0  # sending nonce
        self.locked = dict()  # locked received
        self.transfers = []  # transfers done
        self.balance = self.contract.participants[self.address]['deposit']

        class Partner(object):

            "class mirroring the properties on the other side of the channel"
            address = [a for a in contract.paricipants if a != self.address][0]
            nonce = 0
            locked = dict()
            transfers = []
            balance = self.contract.participants[address]['deposit']

            @property
            def spendable(me):
                return me.balance + me.outstanding_amount - self.outstanding_amount

            @property
            def outstanding_amount(me):
                return sum(t.lock.amount for t in me.locked.values())

            @property
            def locksroot(me):
                return self.mk_locksroot([t.lock for t in me.locked.values()])

        self.partner = Partner()

        self.wasclosed = False

    @property
    def isopen(self):
        return not self.wasclosed and self.contract.isopen

    @property
    def spendable(self):
        return self.balance + self.outstanding_amount - self.partner.outstanding_amount

    @property
    def outstanding_amount(self):
        return sum(t.lock.amount for t in self.locked.values())

    def register_locked_transfer(self, transfer):
        if transfer.recipient == self.address:
            assert transfer.lock.hashlock not in self.locked  # mhmm
            self.locked[transfer.lock.hashlock] = transfer
        else:
            assert transfer.recipient == self.partner.address
            assert transfer.lock.hashlock not in self.partner.locke  # mhmm
            self.partner.locked[transfer.lock.hashlock] = transfer

    @classmethod
    def mk_locksroot(cls, locks):
        "fingerprint of the outstanding amount"
        return merkleroot([sha3(lock.asstring) for lock in locks])

    @property
    def locksroot(self):  # fixme cache!
        return self.mk_locksroot([t.lock for t in self.locked.values()])

    def apply_secret(self, secret):
        """
        the secret releases a lock
        """
        hashlock = sha3(secret)
        if hashlock in self.locked:
            amount = self.locked[hashlock].lock.amount
            self.balance += amount
            self.partner.balance += amount
            del self.locked[hashlock]
        if hashlock in self.partner.locked:
            amount = self.locked[hashlock].lock.amount
            self.balance -= amount
            self.partner.balance += amount
            del self.partner.locked[hashlock]

    def receive(self, transfer):
        assert transfer.recipient == self.address
        if transfer.nonce != self.partner.nonce:
            raise InvalidNonce()

        # update balance with released lock if secret
        if transfer.secret:
            self.apply_secret(transfer.secret)

        # collect funds
        allowance = transfer.balance - self.balance
        assert allowance >= 0
        if allowance > self.partner.spendable:
            raise InsufficientBalance()

        # register locked funds
        if isinstance(transfer, (LockedTransfer, MediatedTransfer)):
            assert transfer.lock.amount > 0
            if allowance + transfer.lock.amount > self.partner.spendable:
                raise InsufficientBalance()
            self.register_locked_transfer(transfer)

        # all checks passed
        self.balance += allowance
        self.partner.balance -= allowance
        self.partner.transfers.append(transfer)
        self.partner.nonce += 1

    def send(self, transfer):
        assert transfer.recipient == self.partner.address
        assert transfer.nonce == self.nonce

        # update balance with released lock if secret
        if transfer.secret:
            self.apply_secret(transfer.secret)

        # dedcuct funds
        allowance = transfer.balance - self.partner.balance
        assert allowance >= 0
        assert allowance <= self.spendable

        # register locked funds
        if isinstance(transfer, (LockedTransfer, MediatedTransfer)):
            assert transfer.lock.amount > 0
            assert allowance + transfer.lock.amount <= self.spendable
            self.register_locked_transfer(transfer)

        # all checks passed
        self.balance -= allowance
        self.partner.balance += allowance
        self.transfers.append(transfer)
        self.nonce += 1

    def create_transfer(self, amount, secret=None):
        assert amount >= 0
        assert self.spendable > amount
        assert self.isopen
        t = Transfer(nonce=self.nonce,
                     asset=self.contract.asset,
                     balance=self.partner.balance + amount,
                     recipient=self.partner.address,
                     locksroot=self.partner.locksroot,  # not changed
                     secret=secret)
        return t

    def create_locked_transfer(self, amount, expiration, hashlock):
        assert self.spendable > amount
        assert self.isopen
        assert expiration > self.contract.chain.block_number

        l = Lock(amount, expiration, hashlock)
        updated_locksroot = self.mk_locksroot([l] + [t.lock for t in self.partner.locks.values()])
        t = LockedTransfer(nonce=self.nonce,
                           asset=self.contract.asset,
                           balance=self.partner.balance,  # not changed
                           recipient=self.partner.address,
                           locksroot=updated_locksroot,
                           lock=l)
        return t

    def close(self):
        pass
