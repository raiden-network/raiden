# -*- coding: utf-8 -*-
from collections import namedtuple
from itertools import chain

from ethereum import slogging

from raiden.transfer.state import BalanceProofState
from raiden.messages import EMPTY_MERKLE_ROOT
from raiden.mtree import Merkletree
from raiden.utils import sha3
from raiden.exceptions import (
    InvalidLocksRoot,
)

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


class BalanceProof(object):
    """ Saves the state required to settle a netting contract. """

    def __init__(self, balance_proof):
        # Mediating locks for which the secret is unknown
        self.hashlocks_to_pendinglocks = dict()

        # Mediating locks for which the secret is known but there is no balance
        # proof unlocking it
        self.hashlocks_to_unclaimedlocks = dict()

        # The latest known balance proof that can be used on-chain
        self.balance_proof = balance_proof

    def unclaimed_merkletree(self):
        all_locks = self.hashlocks_to_pendinglocks.values()
        all_locks.extend(self.hashlocks_to_unclaimedlocks.values())

        # The tree is built from the hash(lock.as_bytes) and not the
        # hash.lockhash, this is required to validate the other fields from the
        # lock, e.g. amount and expiration.
        return [
            lock.lockhashed for lock in all_locks
        ]

    def generate_merkle_tree(self):
        all_lockhashes = self.unclaimed_merkletree()
        return Merkletree(all_lockhashes)

    def merkleroot_for_unclaimed(self):
        tree = self.generate_merkle_tree()
        return tree.merkleroot or EMPTY_MERKLE_ROOT

    def is_pending(self, hashlock):
        """ True if a secret is not known for the given `hashlock`. """
        return hashlock in self.hashlocks_to_pendinglocks

    def is_unclaimed(self, hashlock):
        """ True if a secret is known but we didnt claim it yet.

        A lock is not claimed until the partner sends the secret back.
        """
        return (
            hashlock in self.hashlocks_to_pendinglocks or
            hashlock in self.hashlocks_to_unclaimedlocks
        )

    is_known = is_unclaimed

    def locked(self):
        alllocks = chain(
            self.hashlocks_to_pendinglocks.values(),
            self.hashlocks_to_unclaimedlocks.values(),
        )

        return sum(
            lock.lock.amount
            for lock in alllocks
        )

    def register_balanceproof_without_lock(self, balance_proof, lock):
        lockhashed = sha3(lock.as_bytes)

        if not isinstance(balance_proof, BalanceProofState):
            raise ValueError('balance_proof must be a BalanceProof instance')

        if not self.is_known(lock.hashlock):
            raise ValueError('hashlock is not registered')

        leaves = self.unclaimed_merkletree()
        leaves.remove(lockhashed)
        new_locksroot = Merkletree(leaves).merkleroot

        if balance_proof.locksroot != new_locksroot:
            raise InvalidLocksRoot(new_locksroot, balance_proof.locksroot)

        if lock.hashlock in self.hashlocks_to_pendinglocks:
            del self.hashlocks_to_pendinglocks[lock.hashlock]
        else:
            del self.hashlocks_to_unclaimedlocks[lock.hashlock]

        self.balance_proof = balance_proof

    def register_balanceproof_with_lock(self, balance_proof, lock):
        lockhashed = sha3(lock.as_bytes)

        if not isinstance(balance_proof, BalanceProofState):
            raise ValueError('balance_proof must be a BalanceProof instance')

        if self.is_known(lock.hashlock):
            raise ValueError('hashlock is already registered')

        leaves = self.unclaimed_merkletree()
        leaves.append(lockhashed)
        new_locksroot = Merkletree(leaves).merkleroot

        if balance_proof.locksroot != new_locksroot:
            raise InvalidLocksRoot(new_locksroot, balance_proof.locksroot)

        self.hashlocks_to_pendinglocks[lock.hashlock] = PendingLock(lock, lockhashed)
        self.balance_proof = balance_proof

    def register_balanceproof(self, balance_proof):
        if not isinstance(balance_proof, BalanceProofState):
            raise ValueError('balance_proof must be a BalanceProof instance')

        unclaimed_locksroot = self.merkleroot_for_unclaimed()

        if balance_proof.locksroot != unclaimed_locksroot:
            raise InvalidLocksRoot(unclaimed_locksroot, balance_proof.locksroot)

        self.balance_proof = balance_proof

    def get_lock_by_hashlock(self, hashlock):
        """ Return the corresponding lock for the given `hashlock`. """
        pendinglock = self.hashlocks_to_pendinglocks.get(hashlock)

        if not pendinglock:
            pendinglock = self.hashlocks_to_unclaimedlocks[hashlock]

        return pendinglock.lock

    def register_secret(self, secret, hashlock=None):
        if hashlock is None:
            hashlock = sha3(secret)

        if not self.is_known(hashlock):
            raise ValueError('secret does not correspond to any known lock.')

        if self.is_pending(hashlock):
            pendinglock = self.hashlocks_to_pendinglocks[hashlock]
            del self.hashlocks_to_pendinglocks[hashlock]

            self.hashlocks_to_unclaimedlocks[hashlock] = UnlockPartialProof(
                pendinglock.lock,
                pendinglock.lockhashed,
                secret,
            )

    def release_lock_by_secret(self, secret, hashlock=None):
        if hashlock is None:
            hashlock = sha3(secret)

        if self.is_pending(hashlock):
            pendinglock = self.hashlocks_to_pendinglocks[hashlock]
            del self.hashlocks_to_pendinglocks[hashlock]
            return pendinglock.lock

        elif self.is_unclaimed(hashlock):
            unclaimedlock = self.hashlocks_to_unclaimedlocks[hashlock]
            del self.hashlocks_to_unclaimedlocks[hashlock]
            return unclaimedlock.lock

        raise ValueError('Unknown hashlock')

    def get_known_unlocks(self):
        """ Generate unlocking proofs for the known secrets. """

        tree = self.generate_merkle_tree()

        return [
            self.compute_proof_for_lock(
                partialproof.secret,
                partialproof.lock,
                tree,
            )
            for partialproof in self.hashlocks_to_unclaimedlocks.itervalues()
        ]

    def compute_proof_for_lock(self, secret, lock, tree=None):
        if tree is None:
            tree = self.generate_merkle_tree()

        # forcing bytes because ethereum.abi doesnt work with bytearray
        lock_encoded = bytes(lock.as_bytes)
        lock_hash = sha3(lock_encoded)

        merkle_proof = tree.make_proof(lock_hash)

        return UnlockProof(
            merkle_proof,
            lock_encoded,
            secret,
        )

    def __eq__(self, other):
        if isinstance(other, BalanceProof):
            return (
                self.hashlocks_to_pendinglocks == other.hashlocks_to_pendinglocks and
                self.hashlocks_to_unclaimedlocks == other.hashlocks_to_unclaimedlocks and
                self.balance_proof == other.balance_proof
            )
        return False

    def __ne__(self, other):
        return not self.__eq__(other)
