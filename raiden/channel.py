# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines
import logging
from collections import namedtuple
from itertools import chain

import gevent
from gevent.event import Event
from ethereum import slogging
from ethereum.utils import encode_hex

from raiden.messages import (
    DirectTransfer,
    Lock,
    LockedTransfer,
    TransferTimeout,
)
from raiden.mtree import merkleroot, get_proof
from raiden.utils import sha3, pex, lpex
from raiden.tasks import REMOVE_CALLBACK
from raiden.transfermanager import UnknownAddress

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

# A lock and it's computed hash, this namedtuple is used to keep the
# `sha3(lock.as_bytes)` cached since this value is used to construct the
# merkletree
PendingLock = namedtuple('PendingLock', ('lock', 'lockhashed'))

# The lock and the secret to unlock it, this is all the data required to
# construct an unlock proof. The proof is not calculated because we only need
# it when the contract is closed.
UnlockPartialProof = namedtuple('UnlockProof', ('lock', 'lockhashed', 'secret'))

# The proof that can be used to unlock a secret with a smart contract
UnlockProof = namedtuple('UnlockProof', ('merkle_proof', 'lock_encoded', 'secret'))


class InvalidNonce(Exception):
    pass


class InvalidSecret(Exception):
    pass


class InvalidLocksRoot(Exception):
    def __init__(self, expected_locksroot, got_locksroot):
        Exception.__init__(
            self,
            'Locksroot mismatch. Expected {} but got {}'.format(
                pex(expected_locksroot),
                pex(got_locksroot)
            ))


class InvalidLockTime(Exception):
    pass


class InsufficientBalance(Exception):
    pass


class BalanceProof(object):
    """ Saves the state required to settle a netting contract. """

    def __init__(self):
        # locks that we are mediating but the secret is unknow
        self.hashlock_pendinglocks = dict()

        # locks that we known the secret but our partner hasn't updated it's
        # state yet
        self.hashlock_unclaimedlocks = dict()

        # locks that we known the secret and the partner has update it's state
        # but we don't have an up-to-date transfer to use as a proof
        self.hashlock_unlockedlocks = dict()

        # the latest known transfer with a correct locksroot that can be used
        # as a proof
        self.transfer = None

    def unclaimed_merkletree(self):
        alllocks = chain(
            self.hashlock_pendinglocks.values(),
            self.hashlock_unclaimedlocks.values()
        )
        return [lock.lockhashed for lock in alllocks]

    def merkleroot_for_unclaimed(self):
        alllocks = chain(
            self.hashlock_pendinglocks.values(),
            self.hashlock_unclaimedlocks.values()
        )
        return merkleroot(lock.lockhashed for lock in alllocks)

    def is_pending(self, hashlock):
        """ True if a secret is not known for the given `hashlock`. """
        return hashlock in self.hashlock_pendinglocks

    def is_unclaimed(self, hashlock):
        """ True if a secret is known but we didnt claim it yet.

        A lock is not claimed until the partner send the secret back.
        """
        return (
            hashlock in self.hashlock_pendinglocks or
            hashlock in self.hashlock_unclaimedlocks
        )

    def is_known(self, hashlock):
        """ True if the a lock with the given hashlock was registered before. """
        return (
            hashlock in self.hashlock_pendinglocks or
            hashlock in self.hashlock_unclaimedlocks or
            hashlock in self.hashlock_unlockedlocks
        )

    def locked(self):
        alllocks = chain(
            self.hashlock_pendinglocks.values(),
            self.hashlock_unclaimedlocks.values(),
            # self.hashlock_unlockedlocks.values()
        )

        return sum(
            lock.lock.amount
            for lock in alllocks
        )

    def register_locked_transfer(self, locked_transfer):
        if not isinstance(locked_transfer, LockedTransfer):
            raise ValueError('transfer must be LockedTransfer')

        lock = locked_transfer.lock
        lockhashed = sha3(lock.as_bytes)

        if self.is_known(lock.hashlock):
            raise ValueError('hashlock is already registered')

        merkletree = self.unclaimed_merkletree()
        merkletree.append(lockhashed)
        new_locksroot = merkleroot(merkletree)

        if locked_transfer.locksroot != new_locksroot:
            raise ValueError(
                'locksroot mismatch expected:{} got:{}'.format(
                    pex(new_locksroot),
                    pex(locked_transfer.locksroot),
                )
            )

        self.hashlock_pendinglocks[lock.hashlock] = PendingLock(lock, lockhashed)
        self.transfer = locked_transfer
        self.hashlock_unlockedlocks = dict()

    def register_direct_transfer(self, direct_transfer):
        if not isinstance(direct_transfer, DirectTransfer):
            raise ValueError('transfer must be a DirectTransfer')

        unclaimed_locksroot = self.merkleroot_for_unclaimed()

        if direct_transfer.locksroot != unclaimed_locksroot:
            raise InvalidLocksRoot(unclaimed_locksroot, direct_transfer.locksroot)

        self.transfer = direct_transfer
        self.hashlock_unlockedlocks = dict()

    def get_lock_by_hashlock(self, hashlock):
        """ Return the corresponding lock for the given `hashlock`. """
        pendinglock = self.hashlock_pendinglocks.get(hashlock)

        if pendinglock:
            return pendinglock.lock

        pendinglock = self.hashlock_unclaimedlocks.get(hashlock)

        if pendinglock:
            return pendinglock.lock

        unlockedlock = self.hashlock_unlockedlocks[hashlock]
        return unlockedlock.lock

    def register_secret(self, secret, hashlock=None):
        if hashlock is None:
            hashlock = sha3(secret)

        if not self.is_known(hashlock):
            raise ValueError('secret does not correspond to any known lock.')

        if self.is_pending(hashlock):
            pendinglock = self.hashlock_pendinglocks[hashlock]
            del self.hashlock_pendinglocks[hashlock]

            self.hashlock_unclaimedlocks[hashlock] = UnlockPartialProof(
                pendinglock.lock,
                pendinglock.lockhashed,
                secret,
            )
        elif log.isEnabledFor(logging.DEBUG):
            log.debug(
                'SECRET REGISTERED MORE THAN ONCE hashlock:%s',
                pex(hashlock),
            )

    def release_lock_by_secret(self, secret, hashlock=None):
        if hashlock is None:
            hashlock = sha3(secret)

        if self.is_pending(hashlock):
            pendinglock = self.hashlock_pendinglocks[hashlock]
            del self.hashlock_pendinglocks[hashlock]

            self.hashlock_unlockedlocks[hashlock] = UnlockPartialProof(
                pendinglock.lock,
                pendinglock.lockhashed,
                secret,
            )

            return pendinglock.lock

        elif self.is_unclaimed(hashlock):
            unclaimedlock = self.hashlock_unclaimedlocks[hashlock]
            del self.hashlock_unclaimedlocks[hashlock]

            self.hashlock_unlockedlocks[hashlock] = unclaimedlock

            return unclaimedlock.lock

        raise ValueError('Unknown hashlock')

    def get_known_unlocks(self):
        """ Generate unlocking proofs for the known secrets. """
        allpartialproof = chain(
            self.hashlock_unclaimedlocks.itervalues(),
            self.hashlock_unlockedlocks.itervalues(),
        )

        return [
            self.compute_proof_for_lock(
                partialproof.secret,
                partialproof.lock,
            )
            for partialproof in allpartialproof
        ]

    def compute_proof_for_lock(self, secret, lock):
        alllocks = chain(
            self.hashlock_pendinglocks.values(),
            self.hashlock_unclaimedlocks.values(),
            self.hashlock_unlockedlocks.values()
        )
        merkletree = [l.lockhashed for l in alllocks]

        # forcing bytes because ethereum.abi doesnt work with bytearray
        lock_encoded = bytes(lock.as_bytes)
        lock_hash = sha3(lock_encoded)
        merkle_proof = get_proof(merkletree, lock_hash)

        return UnlockProof(
            merkle_proof,
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

        # amount of asset transferred and unlocked
        self.transferred_amount = 0

        # sequential nonce, current value has not been used.
        # 0 is used in the netting contract to represent the lack of a
        # transfer, so this value must start at 1
        self.nonce = 1

        # contains the last known message with a valid signature and
        # transferred_amount, the secrets revealed since that transfer, and the
        # pending locks
        self.balance_proof = BalanceProof()

    def locked(self):
        """ Return how much asset is locked waiting for a secret. """
        return self.balance_proof.locked()

    def update_contract_balance(self, contract_balance):
        """ Update the contract balance, it must always increase. """
        if contract_balance < self.contract_balance:
            log.error('contract_balance cannot decrease')
            raise ValueError('contract_balance cannot decrease')

        self.contract_balance = contract_balance

    def balance(self, other):
        """ Return the current available balance of the participant. """
        return self.contract_balance - self.transferred_amount + other.transferred_amount

    def distributable(self, other):
        """ Return the available amount of the asset that can be transferred in
        the channel.
        """
        return self.balance(other) - other.locked()

    def compute_merkleroot_with(self, include):
        merkletree = self.balance_proof.unclaimed_merkletree()
        merkletree.append(sha3(include.as_bytes))
        return merkleroot(merkletree)

    def compute_merkleroot_without(self, exclude):
        """ Compute the resulting merkle root if the lock `exclude` is removed. """

        if isinstance(exclude, Lock):
            raise ValueError('exclude must be a Lock')

        merkletree = self.balance_proof.unclaimed_merkletree()

        if exclude.hashlock not in merkletree:
            raise ValueError('unknown lock `exclude`', exclude=exclude)

        exclude_hash = sha3(exclude.as_bytes)
        merkletree.remove(exclude_hash)
        root = merkleroot(merkletree)

        return root

    # api design: using specialized methods to force the user to register the
    # transfer and the lock in a single step
    def register_locked_transfer(self, locked_transfer):
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
        self.balance_proof.register_locked_transfer(locked_transfer)

    def register_direct_transfer(self, direct_transfer):
        self.balance_proof.register_direct_transfer(direct_transfer)

    def register_secret(self, secret):
        """ Register a secret so that it can be used in a balance proof.

        Note:
            This methods needs to be called once a `Secret` message is received
            or a `SecretRevealed` event happens.
        """
        self.balance_proof.register_secret(secret)

    def release_lock(self, partner, secret):
        """ Update the balance by claiming a lock.

        This method needs to be called when the `sender` of the lock sends a
        `Secret` message otherwise the node's locksroot will be out-of-sync and
        messages will be rejected.

        Args:
            secret: The secret being registered.

        Raises:
            InvalidSecret: If there is no lock register for the given secret
                (or `hashlock` if given).
        """
        # Start of the critical read/write section
        lock = self.balance_proof.release_lock_by_secret(secret)
        amount = lock.amount
        partner.transferred_amount += amount
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

    def query_settled(self):
        return self.netting_channel.settled()

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

    def close(self, our_address, first_transfer, second_transfer):
        return self.netting_channel.close(our_address, first_transfer, second_transfer)

    def update_transfer(self, our_address, their_transfer):
        return self.netting_channel.update_transfer(our_address, their_transfer)

    def unlock(self, our_address, unlock_proofs):
        return self.netting_channel.unlock(our_address, unlock_proofs)

    def settle(self):
        return self.netting_channel.settle()


class Channel(object):
    # pylint: disable=too-many-instance-attributes,too-many-arguments

    def __init__(self, our_state, partner_state, external_state,
                 asset_address, reveal_timeout, settle_timeout):

        if settle_timeout <= reveal_timeout:
            # reveal_timeout must be a fraction of the settle_timeout
            raise ValueError('reveal_timeout can not be larger-or-equal to settle_timeout')

        if reveal_timeout < 3:
            # To guarantee that assets won't be lost the expiration needs to
            # decrease at each hop, this is what forces the next hop to reveal
            # the secret with enough time for this node to unlock the lock with
            # the previous.
            #
            # This /should be/ at least:
            #
            #   reveal_timeout = blocks_to_learn + blocks_to_mine * 2
            #
            # Where:
            #
            # - `blocks_to_learn` is the estimated worst case for a given block
            # to propagate to the full network. This is the time to learn a
            # secret revealed throught the blockchain.
            # - `blocks_to_mine * 2` is the estimated worst case for a given
            # transfer to be included in a block. This is the time to close a
            # channel and then to unlock a lock on chain.
            #
            raise ValueError('reveal_timeout must be at least 1')

        if not isinstance(settle_timeout, (int, long)):
            raise ValueError('settle_timeout must be integral')

        if not isinstance(reveal_timeout, (int, long)):
            raise ValueError('reveal_timeout must be integral')

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
        self.on_withdrawable_callbacks = list()  # mapping of transfer to callback list
        self.on_task_completed_callbacks = list()  # XXX naming

    @property
    def isopen(self):
        return self.external_state.isopen()

    @property
    def contract_balance(self):
        """ Return the amount of asset used to open the channel. """
        return self.our_state.contract_balance

    @property
    def transferred_amount(self):
        """ Return how much we transferred to partner. """
        return self.our_state.transferred_amount

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

    def register_withdrawable_callback(self, callback):
        self.on_withdrawable_callbacks.append(callback)

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
                # do not call settle if already settled, the settle_event might
                # not be set if the LogListener is lagging behind.
                settled_block = self.external_state.query_settled()
                if settled_block != 0:
                    self.external_state.set_settled(settled_block)
                    log.info('channel automatically settled')
                    return

                try:
                    # TODO: to remove unecessary JSON-RPC calls, change to an
                    # async version of settle and stop polling if the
                    # settle_event was set
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

    def get_state_for(self, node_address_bin):
        if self.our_state.address == node_address_bin:
            return self.our_state

        if self.partner_state.address == node_address_bin:
            return self.partner_state

        raise Exception('Unknow address {}'.format(encode_hex(node_address_bin)))

    def register_secret(self, secret):
        """ Register a secret.

        This wont claim the lock (update the transferred_amount), it will only
        save the secret in case that a proof needs to be created. This method
        can be used for any of the ends of the channel.

        Note:
            When a secret is revealed a message could be in-transit containing
            the older lockroot, for this reason the recipient cannot update
            it's locksroot at the moment a secret was revealed.

            The protocol is to register the secret so that it can compute a
            proof of balance, if necessary, forward the secret to the sender
            and wait for the update from it. It's the sender duty to order the
            current in-transit (and possible the transfers in queue) transfers
            and the secret/locksroot update.

            The channel and it's queue must be changed in sync, a transfer must
            not be created and while we update the balance_proof.

        Args:
            secret: The secret that releases a locked transfer.
        """
        hashlock = sha3(secret)

        our_known = self.our_state.balance_proof.is_known(hashlock)
        partner_known = self.partner_state.balance_proof.is_known(hashlock)

        if not our_known and not partner_known:
            msg = 'Secret doesnt correspond to a registered hashlock. hashlock:{} asset:{}'.format(
                pex(hashlock),
                pex(self.asset_address),
            )

            raise ValueError(msg)

        if our_known:
            lock = self.our_state.balance_proof.get_lock_by_hashlock(hashlock)

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'SECRET REGISTERED node:%s %s > %s asset:%s hashlock:%s amount:%s',
                    pex(self.our_state.address),
                    pex(self.our_state.address),
                    pex(self.partner_state.address),
                    pex(self.asset_address),
                    pex(hashlock),
                    lock.amount,
                )

            self.our_state.register_secret(secret)

        if partner_known:
            lock = self.partner_state.balance_proof.get_lock_by_hashlock(hashlock)

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'SECRET REGISTERED node:%s %s > %s asset:%s hashlock:%s amount:%s',
                    pex(self.our_state.address),
                    pex(self.partner_state.address),
                    pex(self.our_state.address),
                    pex(self.asset_address),
                    pex(hashlock),
                    lock.amount,
                )

            self.partner_state.register_secret(secret)

    def release_lock(self, secret):
        """ Release a lock for a transfer that was initiated from this node.

        Only the sender of the mediated transfer can release a lock, the
        receiver might know the secret but it needs to wait for a message from
        the initiator. This is because the sender needs to coordinate states
        updates (the hashlock for the transfers that are in transit and/or in
        queue need to be in sync with the state known by the partner).

        Note:
            Releasing a lock should always be accompained by at least one
            Secret message to the partner node.

            The node should also release the locks for the refund transfer.
        """
        hashlock = sha3(secret)

        if not self.partner_state.balance_proof.is_known(hashlock):
            raise ValueError('The secret doesnt unlock any hashlock. hashlock:{} asset:{}'.format(
                pex(hashlock),
                pex(self.asset_address),
            ))

        lock = self.partner_state.balance_proof.get_lock_by_hashlock(hashlock)

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'ASSET UNLOCKED %s > %s asset:%s hashlock:%s lockhash:%s amount:%s',
                pex(self.our_state.address),
                pex(self.partner_state.address),
                pex(self.asset_address),
                pex(hashlock),
                pex(sha3(lock.as_bytes)),
                lock.amount,
            )

        self.partner_state.release_lock(self.our_state, secret)

    def withdraw_lock(self, secret):
        """ A lock was released by the sender, withdraw it's funds and update
        the state.
        """
        hashlock = sha3(secret)

        if not self.our_state.balance_proof.is_known(hashlock):
            msg = 'The secret doesnt withdraw any hashlock. hashlock:{} asset:{}'.format(
                pex(hashlock),
                pex(self.asset_address),
            )
            raise ValueError(msg)

        lock = self.our_state.balance_proof.get_lock_by_hashlock(hashlock)

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'ASSET WITHDRAWN %s < %s asset:%s hashlock:%s lockhash:%s amount:%s',
                pex(self.our_state.address),
                pex(self.partner_state.address),
                pex(self.asset_address),
                pex(hashlock),
                pex(sha3(lock.as_bytes)),
                lock.amount,
            )

        self.our_state.release_lock(self.partner_state, secret)

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
            if log.isEnabledFor(logging.WARN):
                log.warn(
                    'Received a transfer from %s with recipient %s who is not '
                    'a part of the channel',
                    pex(transfer.sender),
                    pex(transfer.recipient),
                )
            raise UnknownAddress(transfer)

    def register_transfer_from_to(self, transfer, from_state, to_state):  # noqa pylint: disable=too-many-branches
        """ Validates and register a signed transfer, updating the channel's state accordingly.

        Note:
            The transfer must be registered before it is sent, not on
            acknowledgement. That is necessary for two reasons:

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
            raise ValueError('Unknown recipient')

        if transfer.sender != from_state.address:
            raise ValueError('Unsigned transfer')

        # nonce is changed only when a transfer is un/registered, if the test
        # fail either we are out of sync, a message out of order, or it's an
        # forged transfer
        if transfer.nonce < 1 or transfer.nonce != from_state.nonce:
            if log.isEnabledFor(logging.WARN):
                log.warn(
                    'Received out of order transfer from %s. Expected '
                    'nonce: %s but got nonce: %s',
                    pex(transfer.sender),
                    from_state.nonce,
                    transfer.nonce,
                )
            raise InvalidNonce(transfer)

        # if the locksroot is out-of-sync (because a transfer was created while
        # a Secret was in traffic) the balance _will_ be wrong, so first check
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
                if log.isEnabledFor(logging.ERROR):
                    log.error(
                        'LOCKSROOT MISMATCH node:%s %s > %s lockhash:%s lockhashes:%s',
                        pex(self.our_state.address),
                        pex(from_state.address),
                        pex(to_state.address),
                        pex(sha3(transfer.lock.as_bytes)),
                        lpex(to_state.balance_proof.unclaimed_merkletree()),
                        expected_locksroot=pex(expected_locksroot),
                        received_locksroot=pex(transfer.locksroot),
                    )

                raise InvalidLocksRoot(expected_locksroot, transfer.locksroot)

            # As a receiver: If the lock expiration is larger than the settling
            # time a secret could be revealed after the channel is settled and
            # we won't be able to claim the asset
            if not transfer.lock.expiration - block_number < self.settle_timeout:
                log.error(
                    "Transfer expiration doesn't allow for correct settlement.",
                    lock_expiration=transfer.lock.expiration,
                    current_block=block_number,
                    settle_timeout=self.settle_timeout,
                )

                raise ValueError("Transfer expiration doesn't allow for correct settlement.")

            if not transfer.lock.expiration - block_number > self.reveal_timeout:
                log.error(
                    'Expiration smaller than the minimum required.',
                    lock_expiration=transfer.lock.expiration,
                    current_block=block_number,
                    reveal_timeout=self.reveal_timeout,
                )

                raise ValueError('Expiration smaller than the minimum required.')

        # only check the balance if the locksroot matched
        if transfer.transferred_amount < from_state.transferred_amount:
            if log.isEnabledFor(logging.ERROR):
                log.error(
                    'NEGATIVE TRANSFER node:%s %s > %s %s',
                    pex(self.our_state.address),
                    pex(from_state.address),
                    pex(to_state.address),
                    transfer,
                )

            raise ValueError('Negative transfer')

        amount = transfer.transferred_amount - from_state.transferred_amount
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
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'REGISTERED LOCK node:%s %s > %s currentlocksroot:%s lockhashes:%s',
                    pex(self.our_state.address),
                    pex(from_state.address),
                    pex(to_state.address),
                    pex(to_state.balance_proof.merkleroot_for_unclaimed()),
                    lpex(to_state.balance_proof.unclaimed_merkletree()),

                    lock_amount=transfer.lock.amount,
                    lock_expiration=transfer.lock.expiration,
                    lock_hashlock=pex(transfer.lock.hashlock),
                    lockhash=pex(sha3(transfer.lock.as_bytes)),
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

        from_state.transferred_amount = transfer.transferred_amount
        from_state.nonce += 1

        if isinstance(transfer, DirectTransfer):
            # if we are the recipient, spawn callback for incoming transfers
            if transfer.recipient == self.our_state.address:
                for callback in self.on_withdrawable_callbacks:
                    gevent.spawn(
                        callback,
                        transfer.asset,
                        transfer.recipient,
                        transfer.sender,  # 'initiator' is sender here
                        transfer.transferred_amount,
                        None  # no hashlock in DirectTransfer
                    )

            # if we are the sender, call the 'success' callback
            elif from_state.address == self.our_state.address:
                callbacks_to_remove = list()
                for callback in self.on_task_completed_callbacks:
                    result = callback(task=None, success=True)  # XXX maybe use gevent.spawn()

                    if result is True:
                        callbacks_to_remove.append(callback)

                for callback in callbacks_to_remove:
                    self.on_task_completed_callbacks.remove(callback)

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'REGISTERED TRANSFER node:%s %s > %s '
                'transfer:%s transferred_amount:%s nonce:%s '
                'current_locksroot:%s',
                pex(self.our_state.address),
                pex(from_state.address),
                pex(to_state.address),
                repr(transfer),
                from_state.transferred_amount,
                from_state.nonce,
                pex(to_state.balance_proof.merkleroot_for_unclaimed()),
            )

    def create_directtransfer(self, amount, identifier):
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

        transferred_amount = from_.transferred_amount + amount
        current_locksroot = to_.balance_proof.merkleroot_for_unclaimed()

        return DirectTransfer(
            identifier=identifier,
            nonce=from_.nonce,
            asset=self.asset_address,
            transferred_amount=transferred_amount,
            recipient=to_.address,
            locksroot=current_locksroot,
        )

    def create_lockedtransfer(self, amount, identifier, expiration, hashlock):
        """ Return a LockedTransfer message.

        This message needs to be signed and registered with the channel before sent.
        """
        if not self.isopen:
            raise ValueError('The channel is closed.')

        block_number = self.external_state.get_block_number()
        timeout = expiration - block_number

        # the lock timeout cannot be larger than the settle timeout (otherwise
        # the smart contract cannot check the locks)
        if timeout >= self.settle_timeout:
            log.debug(
                'Lock expiration is larger than settle timeout.',
                expiration=expiration,
                block_number=block_number,
                settle_timeout=self.settle_timeout,
            )

            raise ValueError('Invalid expiration.')

        # the expiration cannot be lower than the reveal timeout (otherwise we
        # dont have enough time to listen for the ChannelSecretRevealed event)
        if timeout <= self.reveal_timeout:
            log.debug(
                'Lock expiration is lower than reveal timeout.',
                expiration=expiration,
                block_number=block_number,
                reveal_timeout=self.reveal_timeout,
            )

            raise ValueError('Invalid expiration.')

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

        updated_locksroot = to_.compute_merkleroot_with(include=lock)
        transferred_amount = from_.transferred_amount

        return LockedTransfer(
            identifier=identifier,
            nonce=from_.nonce,
            asset=self.asset_address,
            transferred_amount=transferred_amount,
            recipient=to_.address,
            locksroot=updated_locksroot,
            lock=lock,
        )

    def create_mediatedtransfer(self, transfer_initiator, transfer_target, fee,
                                amount, identifier, expiration, hashlock):
        """ Return a MediatedTransfer message.

        This message needs to be signed and registered with the channel before
        sent.

        Args:
            transfer_initiator (address): The node that requested the transfer.
            transfer_target (address): The final destination node of the transfer
            amount (float): How much of an asset is being transferred.
            expiration (int): The maximum block number until the transfer
                message can be received.
        """

        locked_transfer = self.create_lockedtransfer(
            amount,
            identifier,
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
            1,  # TODO: Perhaps add identifier in the refund transfer too?
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
