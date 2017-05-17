# -*- coding: utf-8 -*-
from ethereum import slogging

from raiden.mtree import Merkletree
from raiden.utils import sha3
from raiden.channel.balance_proof import BalanceProof

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class ChannelEndState(object):
    """ Tracks the state of one of the participants in a channel. """

    def __init__(self, participant_address, participant_balance, opened_block):
        # since ethereum only uses integral values we cannot use float/Decimal
        if not isinstance(participant_balance, (int, long)):
            raise ValueError('participant_balance must be an integer.')

        self.contract_balance = participant_balance
        self.address = participant_address

        # amount of token transferred and unlocked
        self.transferred_amount = 0

        # Sequential nonce, current value has not been used, 0 must not be used
        # since in the netting contract it represents null.
        #
        # The nonce value must be inside the netting channel allowed range
        # that is defined in terms of the opened block
        self.nonce = 1 * (opened_block * (2 ** 32))

        # contains the last known message with a valid signature and
        # transferred_amount, the secrets revealed since that transfer, and the
        # pending locks
        self.balance_proof = BalanceProof()

    def locked(self):
        """ Return how much token is locked waiting for a secret. """
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
        """ Return the available amount of the token that can be transferred in
        the channel.
        """
        return self.balance(other) - other.locked()

    def compute_merkleroot_with(self, include):
        """ Compute the resulting merkle root if the lock `include` is added in
        the tree.
        """
        leafs = self.balance_proof.unclaimed_merkletree()
        leafs.append(sha3(include.as_bytes))
        locksroot = Merkletree(leafs).merkleroot

        return locksroot

    # api design: using specialized methods to force the user to register the
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
        """
        # Start of the critical read/write section
        lock = self.balance_proof.release_lock_by_secret(secret)
        amount = lock.amount
        partner.transferred_amount += amount
        # end of the critical read/write section
