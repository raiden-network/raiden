# -*- coding: utf8 -*-
from collections import defaultdict, namedtuple

import gevent
from ethereum import slogging
from ethereum.utils import encode_hex
from gevent.event import Event

from raiden.messages import (
    DirectTransfer,
    Lock,
    LockedTransfer,
    TransferTimeout,
)
from raiden.mtree import merkleroot
from raiden.utils import sha3, pex, lpex
from raiden.tasks import REMOVE_CALLBACK

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

# A lock and it's computed hash, this namedtuple is used to keep the
# `sha3(lock.as_bytes)` cached since this value is used to construct the
# merkletree
PendingLock = namedtuple('PendingLock', ('lock', 'lockhashed'))

# The lock and the secret to unlock it, this is all the data required to
# construct an unlock proof. The proof is not calculated because we only need
# it when the contract is closed.
UnlockPartialProof = namedtuple('UnlockProof', ('lock', 'secret'))

# The proof that can be used to unlock a secret with a smart contract
UnlockProof = namedtuple('UnlockProof', ('merkle_proof', 'lock_encoded', 'secret'))


class InvalidNonce(Exception):
    pass


class InvalidSecret(Exception):
    pass


class InvalidLocksRoot(Exception):
    pass


class InvalidLockTime(Exception):
    pass


class InsufficientBalance(Exception):
    pass


class BalanceProof(object):
    """ Saves the state required to settle a netting contract. """

    def __init__(self, transfer, hashlock_pendinglocks):
        """
        Args:
            transfer: A transfer message object that can be used to close a
            contract.

            The message must be valid, with a correct `nonce`,
            `transfered_amount`, and `locksroot`.

            hashlock_pendinglocks Dict: A mapping from the hashlock to the lock
            containing the locks that are contained in the messages's
            locksroot.
        """
        if not isinstance(hashlock_pendinglocks, dict):
            raise ValueError('hashlock_pendinglocks must be a dictionary')

        # gradualy move locks from pending to unlocked as secrets are revealed,
        # preserve the merkletree and the lock data so that proofs can be
        # calculated.
        self.hashlock_pendinglocks = hashlock_pendinglocks
        self.unlockedlocks = dict()

        merkletree = [
            pendinglock.lockhashed
            for pendinglock in hashlock_pendinglocks.values()
        ]
        self._transfer = transfer
        self._merkletree = merkletree
        self._merkleroot = None

    # api design: transfer and merkletree must be read-only for the life-time
    # of a BalanceProof instance.
    @property
    def transfer(self):
        # XXX: copy the transfer
        return self._transfer

    @property
    def merkletree(self):
        return list(self._merkletree)

    @property
    def merkleroot(self):
        root = self._merkleroot

        if root is None:
            self._merkleroot = root = merkleroot(self._merkletree)

        return root

    def is_pending(self, hashlock):
        """ True if a secret is needed for the given `hashlock`.

        Returns:
            True: If a secret is need for the given `hashlock`.
            False: If the `hashlock` is *unknown*, this could mean the secret
                was revealed or that the `hashlock` is completely unknown.
        """
        return hashlock in self.hashlock_pendinglocks

    def get_pending_lock(self, hashlock):
        """ Return the corresponding lock for the given `hashlock`. """
        pendinglock = self.hashlock_pendinglocks[hashlock]
        return pendinglock.lock

    def register_secret(self, secret, hashlock=None):
        if hashlock is None:
            hashlock = sha3(secret)

        if hashlock not in self.hashlock_pendinglocks:
            raise ValueError('secret does not unlock any pending lock.')

        pendinglock = self.hashlock_pendinglocks[hashlock]
        self.unlockedlocks[hashlock] = UnlockPartialProof(
            pendinglock.lock,
            secret,
        )

        del self.hashlock_pendinglocks[hashlock]

    def get_known_unlocks(self):
        """ Generate unlocking proofs for the known secrets. """
        return [
            self.compute_proof_for_lock(
                partialproof.secret,
                partialproof.lock,
            )
            for partialproof in self.unlockedlocks.values()
        ]

    def get_proof_for_hashlock(self, secret, hashlock):
        if hashlock in self.unlockedlocks:
            secret2, lock, lockhashed = self.unlockedlocks[hashlock]

            if secret != secret2:
                raise ValueError('secret mismatch')

        elif hashlock in self.hashlock_pendinglocks:
            pendinglock = self.hashlock_pendinglocks[hashlock]
            lock = pendinglock.lock

        else:
            raise ValueError('Unknow hashlock')

        return self.compute_proof_for_lock(secret, lock)

    def compute_proof_for_lock(self, secret, lock):
        # forcing bytes because ethereum.abi doesnt work with bytearray
        lock_encoded = bytes(lock.as_bytes)
        lock_hash = sha3(lock_encoded)
        merkle_proof = [lock_hash]
        merkleroot(list(self.merkletree), merkle_proof)

        return UnlockProof(
            [],  # merkle_proof,
            lock_encoded,
            secret,
        )


class ChannelEndState(object):
    """ Tracks the state of one of the participants in a channel. """

    def __init__(self, participant_address, participant_balance):
        # since ethereum only uses integral values we cannot use float/Decimal
        if not isinstance(participant_balance, (int, long)):
            raise ValueError('participant_balance must be an integer.')

        self.contract_balance = participant_balance
        self.address = participant_address

        # amount of asset transfered and unlocked
        self.transfered_amount = 0

        # sequential nonce, current value has not been used.
        # 0 is used in the netting contract to represent the lack of a
        # transfer, so this value must start at 1
        self.nonce = 1

        # contains the last known message with a valid signature and
        # transfered_amount, the secrets revealed since that transfer, and the
        # pending locks
        self.balance_proof = BalanceProof(None, dict())

    def locked(self):
        """ Return how much asset is locked waiting for a secret. """
        pendinglock_list = self.balance_proof.hashlock_pendinglocks.values()

        return sum(
            pendinglock.lock.amount
            for pendinglock in pendinglock_list
        )

    def update_contract_balance(self, contract_balance):
        """ Update the contract balance, it must always increase. """
        if contract_balance < self.contract_balance:
            log.error('contract_balance cannot decrease')
            raise ValueError('contract_balance cannot decrease')

        self.contract_balance = contract_balance

    def balance(self, other):
        """ Return the current available balance of the participant. """
        return self.contract_balance - self.transfered_amount + other.transfered_amount

    def distributable(self, other):
        """ Return the available amount of the asset that can be transfered in
        the channel.
        """
        return self.balance(other) - other.locked()

    def compute_merkleroot(self):
        """ Compute the resulting merkle root if the lock `include` is added. """
        if self.balance_proof is None:
            return ''

        pendinglock_list = self.balance_proof.hashlock_pendinglocks.values()
        temporary_tree = [
            pendinglock.lockhashed
            for pendinglock in pendinglock_list
        ]

        root = merkleroot(temporary_tree)

        return root

    def compute_merkleroot_with(self, include, lockhashed=None):
        """ Compute the resulting merkle root if the lock `include` is added. """

        if not isinstance(include, Lock):
            raise ValueError('include must be a Lock')

        pendinglock_list = self.balance_proof.hashlock_pendinglocks.values()
        temporary_tree = [
            pendinglock.lockhashed
            for pendinglock in pendinglock_list
        ]

        if lockhashed is None:
            include_hash = sha3(include.as_bytes)
        else:
            include_hash = lockhashed

        temporary_tree.append(include_hash)
        root = merkleroot(temporary_tree)

        return root

    def compute_merkleroot_without(self, exclude):
        """ Compute the resulting merkle root if the lock `exclude` is removed. """

        if isinstance(exclude, Lock):
            raise ValueError('exclude must be a Lock')

        if exclude.hashlock not in self.balance_proof.hashlock_pendinglocks:
            raise ValueError('unknown lock `exclude`', exclude=exclude)

        pendinglock_list = self.balance_proof.hashlock_pendinglocks.values()
        temporary_tree = [
            pendinglock.lockhashed
            for pendinglock in pendinglock_list
        ]

        exclude_hash = sha3(exclude.as_bytes)
        temporary_tree.remove(exclude_hash)
        root = merkleroot(temporary_tree)

        return root

    # api design: using specialized methods to force the user to register the
    # transfer and the lock in a single step
    def register_locked_transfer(self, transfer):
        """ Register the latest known transfer.

        The sender needs to use this method before sending a locked transfer,
        otherwise the calculate locksroot of the transfer message will be
        invalid and the transfer will be rejected by the partner. Since the
        sender wants the transfer to be accepted by the receiver otherwise the
        transfer won't proceed and the sender won't receive it's fee.

        The receiver needs to use this method to update the container with a
        _valid_ transfer, otherwise the locksroot will not contain the pending
        transfer. The receiver needs to ensure that the merkle root has the
        hashlock include, otherwise it won't be able to claim it.

        Args:
            transfer (LockedTransfer): The transfer to be added.
        """
        if not isinstance(transfer, LockedTransfer):
            raise ValueError('transfer must be LockedTransfer')

        lock = transfer.lock

        if self.balance_proof.is_pending(lock.hashlock):
            raise ValueError('hashlock is already registered')

        # this value is being cached by:
        # - copying the hashlock_pendinglocks from the previous `balance_proof`
        # preserving the computed hashes
        # - computing it here and using this value for the compute_merkleroot_with
        # - reusing hashlock_pendinglocks in compute_merkleroot_with/out methods
        lockhashed = sha3(lock.as_bytes)

        new_locksroot = self.compute_merkleroot_with(lock, lockhashed=lockhashed)
        if transfer.locksroot != new_locksroot:
            raise ValueError(
                'locksroot mismatch expected:{} got:{}'.format(
                    pex(new_locksroot),
                    pex(transfer.locksroot),
                )
            )

        hashlock_pendinglocks = dict(self.balance_proof.hashlock_pendinglocks)
        hashlock_pendinglocks[lock.hashlock] = PendingLock(lock, lockhashed)

        self.balance_proof = BalanceProof(
            transfer,
            hashlock_pendinglocks,
        )

    def register_direct_transfer(self, transfer):
        if not isinstance(transfer, DirectTransfer):
            raise ValueError('transfer must be a DirectTransfer')

        pendinglock_list = self.balance_proof.hashlock_pendinglocks.values()
        temporary_tree = [
            pendinglock.lockhashed
            for pendinglock in pendinglock_list
        ]
        current_locksroot = merkleroot(temporary_tree)

        if transfer.locksroot != current_locksroot:
            raise ValueError(
                'locksroot mismatch',
                expected=current_locksroot,
                sent=transfer.locksroot,
            )

        hashlock_pendinglocks = dict(self.balance_proof.hashlock_pendinglocks)

        self.balance_proof = BalanceProof(
            transfer,
            hashlock_pendinglocks,
        )

    def register_secret(self, partner, secret):
        """ Register the secret and update the balances for the unlocked
        amount.

        This methods needs to be called once a `Secret` message is received or
        a `SecretRevealed` event happens, otherwise the nodes can get
        out-of-sync and messages will be rejected.

        Note:
            As a sender remove the freed hashlock to avoid double netting of a
            locked transfer (as a receiver this is "just" synching).

        Args:
            partner: The partner end from which we are receiving, this is
                required to keep both ends in sync.
            secret: The secret being registered.

        Raises:
            InvalidSecret: If there is no lock register for the given secret
                (or `hashlock` if given).

        Returns:
            float: The amount that was locked.
        """
        # XXX: The secret is being discarded right away, it needs to be saved
        # at least until the next partner's message with an updated balance and
        # locksroot that acknowledges the unlocked asset
        hashlock = sha3(secret)

        # Start of the critical read/write section
        #
        # The balance and lockroot work hand-in-hand, both values need to be
        # synchronized at all times with the penalty of losing asset.
        #
        # This section works for cooperative multitasking, for preempted
        # multitasking synchronization needs to be done.

        if not self.balance_proof.is_pending(hashlock):
            raise InvalidSecret(hashlock)

        lock = self.balance_proof.get_pending_lock(hashlock)
        amount = lock.amount

        # Indirectly update balance by setting the partner's transfered_amount
        partner.transfered_amount += amount

        self.balance_proof.register_secret(secret, hashlock=hashlock)
        # end of the critical read/write section


class ChannelExternalState(object):
    def __init__(self, register_block_alarm, register_channel_for_hashlock,
                 get_block_number, netting_channel):
        self.register_block_alarm = register_block_alarm
        self.register_channel_for_hashlock = register_channel_for_hashlock
        self.get_block_number = get_block_number

        self.netting_channel = netting_channel

        # api design: allow the user to access these attributes as read-only
        # but force him to use the `set_` methods, the use of methods is to
        # signal that additinal code might get executed
        self._opened_block = netting_channel.opened()
        self._closed_block = netting_channel.closed()
        self._settled_block = netting_channel.settled()

        self.callbacks_opened = list()
        self.callbacks_closed = list()
        self.callbacks_settled = list()

    @property
    def opened_block(self):
        return self._opened_block

    @property
    def closed_block(self):
        return self._closed_block

    @property
    def settled_block(self):
        return self._settled_block

    def set_opened(self, block_number):
        if self._opened_block != 0:
            raise RuntimeError('channel is already open')

        self._opened_block = block_number

        for callback in self.callbacks_opened:
            callback(block_number)

    def set_closed(self, block_number):
        if self._closed_block != 0:
            raise RuntimeError('channel is already closed')

        self._closed_block = block_number

        for callback in self.callbacks_closed:
            callback(block_number)

    def set_settled(self, block_number):
        if self._settled_block != 0:
            raise RuntimeError('channel is already settled')

        self._settled_block = block_number

        for callback in self.callbacks_settled:
            callback(block_number)

    def callback_on_opened(self, callback):
        if self._opened_block != 0:
            callback(self._opened_block)

        self.callbacks_opened.append(callback)

    def callback_on_closed(self, callback):
        if self._closed_block != 0:
            callback(self._closed_block)

        self.callbacks_closed.append(callback)

    def callback_on_settled(self, callback):
        if self._settled_block != 0:
            callback(self._settled_block)

        self.callbacks_settled.append(callback)

    def isopen(self):
        if self._closed_block != 0:
            return False

        if self._opened_block != 0:
            return True

        return False

    def update_transfer(self, our_address, transfer):
        return self.netting_channel.update_transfer(our_address, transfer)

    def unlock(self, our_address, unlock_proofs):
        return self.netting_channel.unlock(our_address, unlock_proofs)

    def settle(self):
        return self.netting_channel.settle()


class Channel(object):
    # pylint: disable=too-many-instance-attributes,too-many-arguments

    def __init__(self, our_state, partner_state, external_state,
                 asset_address, reveal_timeout, settle_timeout):

        self.our_state = our_state
        self.partner_state = partner_state

        self.asset_address = asset_address
        self.reveal_timeout = reveal_timeout
        self.settle_timeout = settle_timeout
        self.external_state = external_state

        self.open_event = Event()
        self.close_event = Event()
        self.settle_event = Event()

        external_state.callback_on_opened(lambda _: self.open_event.set())
        external_state.callback_on_closed(lambda _: self.close_event.set())
        external_state.callback_on_settled(lambda _: self.settle_event.set())

        external_state.callback_on_closed(self.channel_closed)

        self.received_transfers = []
        self.sent_transfers = []  #: transfers that were sent, required for settling
        self.transfer_callbacks = defaultdict(list)  # mapping of transfer to callback list

    @property
    def isopen(self):
        return self.external_state.isopen()

    @property
    def contract_balance(self):
        """ Return the amount of asset used to open the channel. """
        return self.our_state.contract_balance

    @property
    def transfered_amount(self):
        """ Return how much we transfered to partner. """
        return self.our_state.transfered_amount

    @property
    def balance(self):
        """ Return our current balance.

        Balance is equal to `initial_deposit + received_amount - sent_amount`,
        were both `receive_amount` and `sent_amount` are unlocked.
        """
        return self.our_state.balance(self.partner_state)

    @property
    def distributable(self):
        """ Return the available amount of the asset that our end of the
        channel can transfer to the partner.
        """
        return self.our_state.distributable(self.partner_state)

    @property
    def locked(self):
        """ Return the current amount of our asset that is locked waiting for a
        secret.

        The locked value is equal to locked transfers that have being
        initialized but the secret has not being revealed.
        """
        return self.partner_state.locked()

    @property
    def outstanding(self):
        return self.our_state.locked()

    def channel_closed(self, block_number):
        self.external_state.register_block_alarm(self.blockalarm_for_settle)

        balance_proof = self.partner_state.balance_proof

        transfer = balance_proof.transfer
        unlock_proofs = balance_proof.get_known_unlocks()

        self.external_state.update_transfer(self.our_state.address, transfer)
        self.external_state.unlock(self.our_state.address, unlock_proofs)

    def blockalarm_for_settle(self, block_number):
        def _settle():
            for _ in range(3):
                try:
                    self.external_state.settle()
                except:
                    log.exception('Timedout while calling settle')

                # wait for the settle event, it could be our transaction or our
                # partner's
                self.settle_event.wait(0.5)

                if self.settle_event.is_set():
                    log.info('channel automatically settled')
                    return

        if self.external_state.closed_block + self.settle_timeout >= block_number:
            gevent.spawn(_settle)  # don't block the alarm
            return REMOVE_CALLBACK

    def handle_callbacks(self, transfer):
        for callback in self.transfer_callbacks[transfer]:
            callback(None, True)

        del self.transfer_callbacks[transfer]

    def get_state_for(self, node_address_bin):
        if self.our_state.address == node_address_bin:
            return self.our_state

        if self.partner_state.address == node_address_bin:
            return self.partner_state

        raise Exception('Unknow address {}'.format(encode_hex(node_address_bin)))

    def register_secret(self, secret):
        """ Claim locked transfer from any of the ends of the channel.

        Args:
            secret: The secret that releases a locked transfer.
        """
        hashlock = sha3(secret)

        # receiving a secret (releasing our funds)
        if self.our_state.balance_proof.is_pending(hashlock):
            lock = self.our_state.balance_proof.get_pending_lock(hashlock)

            log.debug('ASSET UNLOCKED node:{} asset:{} hashlock:{} amount:{}'.format(
                pex(self.our_state.address),
                pex(self.asset_address),
                pex(hashlock),
                lock.amount,
            ))
            self.our_state.register_secret(self.partner_state, secret)

        # sending a secret (updating the mirror)
        elif self.partner_state.balance_proof.is_pending(hashlock):
            lock = self.partner_state.balance_proof.get_pending_lock(hashlock)

            log.debug('ASSET UNLOCKED node:{} asset:{} hashlock:{} amount:{}'.format(
                pex(self.our_state.address),
                pex(self.asset_address),
                pex(hashlock),
                lock.amount,
            ))
            self.partner_state.register_secret(self.our_state, secret)
        else:
            raise ValueError('The secret doesnt unlock any hashlock')

    def register_transfer(self, transfer, callback=None):
        """ Register a signed transfer, updating the channel's state accordingly. """

        if transfer.recipient == self.partner_state.address:
            self.register_transfer_from_to(
                transfer,
                from_state=self.our_state,
                to_state=self.partner_state,
            )

            self.sent_transfers.append(transfer)

            if callback:
                self.transfer_callbacks[transfer].append(callback)

        elif transfer.recipient == self.our_state.address:
            self.register_transfer_from_to(
                transfer,
                from_state=self.partner_state,
                to_state=self.our_state,
            )
            self.received_transfers.append(transfer)

        else:
            raise ValueError('Invalid address')

    def register_transfer_from_to(self, transfer, from_state, to_state):  # noqa pylint: disable=too-many-branches
        """ Validates and register a signed transfer, updating the channel's state accordingly.

        Note:
            The transfer must be register before it is sent, not on
            acknowledgement. That is necessary for to reasons:

            - Guarantee that the transfer is valid.
            - Avoiding sending a new transaction without funds.

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

        # nonce is changed only when a transfer is un/registered, if the test
        # fail either we are out of sync, a message out of order, or it's an
        # forged transfer
        if transfer.nonce < 1 or transfer.nonce != from_state.nonce:
            raise InvalidNonce(transfer)

        # if the locksroot is out-of-sync (because a transfer was created while
        # a Secret was in trafic) the balance _will_ be wrong, so first check
        # the locksroot and then the balance
        if isinstance(transfer, LockedTransfer):
            block_number = self.external_state.get_block_number()

            if to_state.balance_proof.is_pending(transfer.lock.hashlock):
                raise ValueError('hashlock is already registered')

            # As a receiver: Check that all locked transfers are registered in
            # the locksroot, if any hashlock is missing there is no way to
            # claim it while the channel is closing
            expected_locksroot = to_state.compute_merkleroot_with(transfer.lock)
            if expected_locksroot != transfer.locksroot:
                log.error(
                    'LOCKSROOT MISMATCH node:{} {} > {}'.format(
                        pex(self.our_state.address),
                        pex(from_state.address),
                        pex(to_state.address),
                        pex(self.partner_state.address),
                    ),
                    expected_locksroot=pex(expected_locksroot),
                    received_locksroot=pex(transfer.locksroot),
                    current_locksroot=pex(to_state.balance_proof.merkleroot),
                )

                raise InvalidLocksRoot(transfer)

            # As a receiver: If the lock expiration is larger than the settling
            # time a secret could be revealed after the channel is settled and
            # we won't be able to claim the asset
            if not transfer.lock.expiration - block_number < self.settle_timeout:
                log.error(
                    "Transfer expiration doesn't allow for corret settlement.",
                    lock_expiration=transfer.lock.expiration,
                    current_block=block_number,
                    settle_timeout=self.settle_timeout,
                )

                raise ValueError("Transfer expiration doesn't allow for corret settlement.")

            if not transfer.lock.expiration - block_number > self.reveal_timeout:
                log.error(
                    'Expiration smaller too small.',
                    lock_expiration=transfer.lock.expiration,
                    current_block=block_number,
                    reveal_timeout=self.reveal_timeout,
                )

                raise ValueError('Expiration smaller than the minimum required.')

        if isinstance(transfer, DirectTransfer) and transfer.secret:
            raise NotImplementedError('DirectTransfer with a secret is not fully tested')
            # hashlock = sha3(transfer.secret)
            # lock = to_state.locked[hashlock]
            # if to_state.compute_merkleroot_without(lock) != transfer.locksroot:
            #     raise InvalidLocksRoot(hashlock)

        # only check the balance if the locksroot matched
        if transfer.transfered_amount < from_state.transfered_amount:
            msg = 'NEGATIVE TRANSFER node:{} {} > {} {}'.format(
                pex(self.our_state.address),
                pex(from_state.address),
                pex(to_state.address),
                transfer,
            )
            log.error(msg)
            raise ValueError('Negative transfer')

        amount = transfer.transfered_amount - from_state.transfered_amount
        distributable = from_state.distributable(to_state)

        if amount > distributable:
            raise InsufficientBalance(transfer)

        if isinstance(transfer, LockedTransfer):
            if amount + transfer.lock.amount > distributable:
                raise InsufficientBalance(transfer)

        # all checks need to be done before the internal state of the channel
        # is changed, otherwise if a check fails and state was changed the
        # channel will be left trashed

        if isinstance(transfer, LockedTransfer):
            log.debug(
                'REGISTERED LOCK node:{} from:{} to:{}'.format(
                    pex(self.our_state.address),
                    pex(from_state.address),
                    pex(to_state.address),
                ),
                lock_amount=transfer.lock.amount,
                lock_expiration=transfer.lock.expiration,
                lock_hashlock=pex(transfer.lock.hashlock),
                hashlock_list=lpex(to_state.balance_proof.merkletree),
            )

            to_state.register_locked_transfer(transfer)

            # register this channel as waiting for the secret (the secret can
            # be revealed through a message or an blockchain log)
            self.external_state.register_channel_for_hashlock(
                self,
                transfer.lock.hashlock,
            )

        if isinstance(transfer, DirectTransfer):
            to_state.register_direct_transfer(transfer)

            if transfer.secret:
                log.debug(
                    'REGISTERED SECRET node:{} from:{} to:{}'.format(
                        pex(self.our_state.address),
                        pex(from_state.address),
                        pex(to_state.address),
                    ),
                    lock_hashlock=pex(sha3(transfer.secret)),
                    lock_secret=pex(transfer.secret),
                )

                to_state.register_secret(
                    from_state,
                    transfer.secret,
                )

        from_state.transfered_amount = transfer.transfered_amount
        from_state.nonce += 1

        log.debug(
            'REGISTERED TRANSFER node:{} from:{} to:{} '
            'transfer:{} transfered_amount:{} nonce:{} '
            'current_locksroot: {}'.format(
                pex(self.our_state.address),
                pex(from_state.address),
                pex(to_state.address),
                repr(transfer),
                from_state.transfered_amount,
                from_state.nonce,
                pex(to_state.balance_proof.merkleroot),
            )
        )

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

        # start of critical read section
        transfered_amount = from_.transfered_amount + amount
        current_locksroot = to_.compute_merkleroot()
        # end of critical read section

        return DirectTransfer(
            nonce=from_.nonce,
            asset=self.asset_address,
            transfered_amount=transfered_amount,
            recipient=to_.address,
            locksroot=current_locksroot,
            secret=secret,
        )

    def create_lockedtransfer(self, amount, expiration, hashlock):
        """ Return a LockedTransfer message.

        This message needs to be signed and registered with the channel before sent.
        """
        if not self.isopen:
            raise ValueError('The channel is closed')

        block_number = self.external_state.get_block_number()

        # expiration is not sufficient for guarantee settling
        if expiration - block_number >= self.settle_timeout:
            log.debug(
                "Transfer expiration doesn't allow for corret settlement.",
                expiration=expiration,
                block_number=block_number,
                settle_timeout=self.settle_timeout,
            )

            raise ValueError('Invalid expiration')

        if expiration - self.reveal_timeout < block_number:
            log.debug(
                'Expiration smaller than the minimum requried.',
                expiration=expiration,
                block_number=block_number,
                reveal_timeout=self.reveal_timeout,
            )

            raise ValueError('Invalid expiration')

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

        # start of critical read section
        transfered_amount = from_.transfered_amount
        updated_locksroot = to_.compute_merkleroot_with(include=lock)
        # end of critical read section

        return LockedTransfer(
            nonce=from_.nonce,
            asset=self.asset_address,
            transfered_amount=transfered_amount,
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

    def create_refundtransfer_for(self, transfer):
        """ Return RefundTransfer for `transfer`. """
        lock = transfer.lock

        if not self.our_state.balance_proof.is_pending(lock.hashlock):
            raise ValueError('Unknow hashlock')

        locked_transfer = self.create_lockedtransfer(
            lock.amount,
            lock.expiration,
            lock.hashlock,
        )

        cancel_transfer = locked_transfer.to_refundtransfer()

        return cancel_transfer

    def create_timeouttransfer_for(self, transfer):
        """ Return a TransferTimeout for `transfer`. """
        lock = transfer.lock

        if not self.our_state.balance_proof.is_pending(lock.hashlock):
            raise ValueError('Unknow hashlock')

        return TransferTimeout(
            transfer.hash,
            lock.hashlock,
        )
