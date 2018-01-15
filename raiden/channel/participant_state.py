# -*- coding: utf-8 -*-
from collections import namedtuple
from itertools import chain

from ethereum import slogging

from raiden.exceptions import InvalidLocksRoot
from raiden.transfer.merkle_tree import (
    EMPTY_MERKLE_TREE,
    EMPTY_MERKLE_ROOT,
    LEAVES,
    compute_layers,
    compute_merkleproof_for,
    merkleroot,
)
from raiden.transfer.state import BalanceProofState, MerkleTreeState
from raiden.utils import sha3

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

# A lock and its computed hash, this namedtuple is used to keep the
# `sha3(lock.as_bytes)` cached since this value is used to construct the
# merkletree
PendingLock = namedtuple('PendingLock', ('lock', 'lockhashed'))

# The lock and the secret to unlock it, this is all the data required to
# construct an unlock proof. The proof is not calculated because we only need
# it when the contract is closed.
UnlockPartialProof = namedtuple('UnlockPartialProof', ('lock', 'lockhashed', 'secret'))

# The proof that can be used to unlock a secret with a smart contract
UnlockProof = namedtuple('UnlockProof', ('merkle_proof', 'lock_encoded', 'secret'))


class ChannelEndState:
    """ Tracks the state of one of the participants in a channel. """

    def __init__(self, participant_address, participant_balance, balance_proof, merkletree):

        # since ethereum only uses integral values we cannot use float/Decimal
        if not isinstance(participant_balance, int):
            raise ValueError('participant_balance must be an integer.')

        # This participant's on-chain balance
        self.contract_balance = participant_balance

        # This participant's address
        self.address = participant_address

        # Locks from mediated transfers for which the secret is unknown.
        self.hashlocks_to_pendinglocks = dict()

        # locks from mediated transfers for which the secret is known but there
        # is no balance proof unlocking it.
        self.hashlocks_to_unclaimedlocks = dict()

        # A merkletree of the keccak hash of the locks.
        self.merkletree = merkletree

        # The latest known balance proof that can be used on-chain, may be None.
        self.balance_proof = balance_proof

    @property
    def transferred_amount(self):
        if self.balance_proof:
            return self.balance_proof.transferred_amount
        return 0

    @property
    def amount_locked(self):
        alllocks = chain(
            self.hashlocks_to_pendinglocks.values(),
            self.hashlocks_to_unclaimedlocks.values(),
        )

        return sum(
            lock.lock.amount
            for lock in alllocks
        )

    @property
    def nonce(self):
        if self.balance_proof:
            return self.balance_proof.nonce
        return None

    def balance(self, other):
        return self.contract_balance - self.transferred_amount + other.transferred_amount

    def distributable(self, other):
        return self.balance(other) - self.amount_locked

    def is_known(self, hashlock):
        """ True if the `hashlock` corresponds to a known lock. """
        return (
            hashlock in self.hashlocks_to_pendinglocks or
            hashlock in self.hashlocks_to_unclaimedlocks
        )

    def is_locked(self, hashlock):
        """ True if the `hashlock` is known and the correspoding secret is not. """
        return hashlock in self.hashlocks_to_pendinglocks

    def update_contract_balance(self, contract_balance):
        """ Update the contract balance, it must always increase.

        Raises:
            ValueError: If the `contract_balance` is smaller than the current
            balance.
        """
        if contract_balance < self.contract_balance:
            log.error('contract_balance cannot decrease')
            raise ValueError('contract_balance cannot decrease')

        self.contract_balance = contract_balance

    def get_lock_by_hashlock(self, hashlock):
        lock = self.hashlocks_to_pendinglocks.get(hashlock)

        if lock is None:
            lock = self.hashlocks_to_unclaimedlocks.get(hashlock)

        return lock.lock

    def compute_merkleroot_with(self, include):
        """ Compute the resulting merkle root if the lock `include` is added in
        the tree.
        """
        if not self.is_known(include.hashlock):
            leaves = list(self.merkletree.layers[LEAVES])
            leaves.append(sha3(include.as_bytes))

            tree_with = MerkleTreeState(compute_layers(leaves))
            locksroot = merkleroot(tree_with)
        else:
            locksroot = merkleroot(self.merkletree)

        return locksroot

    def compute_merkleroot_without(self, without):
        """ Compute the resulting merkle root if the lock `include` is added in
        the tree.
        """
        if not self.is_known(without.hashlock):
            raise ValueError('unknown lock', lock=without)

        leaves = list(self.merkletree.layers[LEAVES])
        leaves.remove(sha3(without.as_bytes))

        if leaves:
            tree_without = MerkleTreeState(compute_layers(leaves))
            locksroot = merkleroot(tree_without)
        else:
            locksroot = EMPTY_MERKLE_ROOT

        return locksroot

    # Api design: using specialized methods to force the user to register the
    # transfer and the lock in a single step

    def register_locked_transfer(self, locked_transfer):
        """ Register the latest known transfer.

        The sender needs to use this method before sending a locked transfer,
        otherwise the calculate locksroot of the transfer message will be
        invalid and the transfer will be rejected by the partner. Since the
        sender wants the transfer to be accepted by the receiver otherwise the
        transfer won't proceed and the sender won't receive their fee.

        The receiver needs to use this method to update the container with a
        _valid_ transfer, otherwise the locksroot will not contain the pending
        transfer. The receiver needs to ensure that the merkle root has the
        hashlock included, otherwise it won't be able to claim it.

        Args:
            transfer (LockedTransfer): The transfer to be added.

        Raises:
            InvalidLocksRoot: If the merkleroot of `locked_transfer` does not
            match with the expected value.

            ValueError: If the transfer contains a lock that was registered
            previously.
        """
        balance_proof = locked_transfer.to_balanceproof()
        lock = locked_transfer.lock
        lockhashed = sha3(lock.as_bytes)

        if self.is_known(lock.hashlock):
            raise ValueError('hashlock is already registered')

        leaves = list(self.merkletree.layers[LEAVES])
        leaves.append(lockhashed)

        newtree = MerkleTreeState(compute_layers(leaves))
        locksroot = merkleroot(newtree)

        if balance_proof.locksroot != locksroot:
            raise InvalidLocksRoot(locksroot, balance_proof.locksroot)

        self.hashlocks_to_pendinglocks[lock.hashlock] = PendingLock(lock, lockhashed)
        self.balance_proof = balance_proof
        self.merkletree = newtree

    def register_direct_transfer(self, direct_transfer):
        """ Register a direct_transfer.

        Raises:
            InvalidLocksRoot: If the merkleroot of `direct_transfer` does not
            match the current value.
        """
        balance_proof = direct_transfer.to_balanceproof()

        if balance_proof.locksroot != merkleroot(self.merkletree):
            raise InvalidLocksRoot(merkleroot(self.merkletree), balance_proof.locksroot)

        self.balance_proof = balance_proof

    def register_secretmessage(self, message_secret):
        balance_proof = message_secret.to_balanceproof()
        hashlock = sha3(message_secret.secret)
        pendinglock = self.hashlocks_to_pendinglocks.get(hashlock)

        if not pendinglock:
            pendinglock = self.hashlocks_to_unclaimedlocks[hashlock]

        lock = pendinglock.lock
        lockhashed = sha3(lock.as_bytes)

        if not isinstance(balance_proof, BalanceProofState):
            raise ValueError('balance_proof must be a BalanceProof instance')

        if not self.is_known(lock.hashlock):
            raise ValueError('hashlock is not registered')

        leaves = list(self.merkletree.layers[LEAVES])
        leaves.remove(lockhashed)

        if leaves:
            layers = compute_layers(leaves)
            new_merkletree = MerkleTreeState(layers)
            new_locksroot = merkleroot(new_merkletree)
        else:
            new_merkletree = EMPTY_MERKLE_TREE
            new_locksroot = EMPTY_MERKLE_ROOT

        if balance_proof.locksroot != new_locksroot:
            raise InvalidLocksRoot(new_locksroot, balance_proof.locksroot)

        if lock.hashlock in self.hashlocks_to_pendinglocks:
            del self.hashlocks_to_pendinglocks[lock.hashlock]
        else:
            del self.hashlocks_to_unclaimedlocks[lock.hashlock]

        self.merkletree = new_merkletree
        self.balance_proof = balance_proof

    def register_secret(self, secret):
        """ Register a secret so that it can be used in a balance proof.

        Note:
            This methods needs to be called once a `Secret` message is received
            or a `SecretRevealed` event happens.

        Raises:
            ValueError: If the hashlock is not known.
        """
        hashlock = sha3(secret)

        if not self.is_known(hashlock):
            raise ValueError('secret does not correspond to any hashlock')

        if self.is_locked(hashlock):
            pendinglock = self.hashlocks_to_pendinglocks[hashlock]
            del self.hashlocks_to_pendinglocks[hashlock]

            self.hashlocks_to_unclaimedlocks[hashlock] = UnlockPartialProof(
                pendinglock.lock,
                pendinglock.lockhashed,
                secret,
            )

    def get_known_unlocks(self):
        """ Generate unlocking proofs for the known secrets. """

        tree = self.merkletree

        return [
            self.compute_proof_for_lock(
                partialproof.secret,
                partialproof.lock,
                tree,
            )
            for partialproof in self.hashlocks_to_unclaimedlocks.values()
        ]

    def compute_proof_for_lock(self, secret, lock, tree=None):
        if tree is None:
            tree = self.merkletree

        # forcing bytes because ethereum.abi doesn't work with bytearray
        lock_encoded = bytes(lock.as_bytes)
        lock_hash = sha3(lock_encoded)

        merkle_proof = compute_merkleproof_for(tree, lock_hash)

        return UnlockProof(
            merkle_proof,
            lock_encoded,
            secret,
        )

    def __eq__(self, other):
        if isinstance(other, ChannelEndState):
            return (
                self.contract_balance == other.contract_balance and
                self.address == other.address and
                self.hashlocks_to_pendinglocks == other.hashlocks_to_pendinglocks and
                self.hashlocks_to_unclaimedlocks == other.hashlocks_to_unclaimedlocks and
                self.merkletree == other.merkletree and
                self.balance_proof == other.balance_proof
            )
        return False

    def __ne__(self, other):
        return not self.__eq__(other)
