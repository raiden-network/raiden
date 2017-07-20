# -*- coding: utf-8 -*-
import logging

from gevent.event import Event
from ethereum import slogging
from ethereum.utils import encode_hex

from raiden.messages import (
    DirectTransfer,
    Lock,
    LockedTransfer,
)
from raiden.utils import sha3, pex, lpex
from raiden.exceptions import (
    InsufficientBalance,
    InvalidLocksRoot,
    InvalidNonce,
    UnknownAddress,
)
from raiden.transfer.state_change import Block
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLED,
    CHANNEL_STATE_INITIALIZING,
)
from raiden.transfer.mediated_transfer.state_change import (
    ContractReceiveClosed,
    ContractReceiveSettled,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class ChannelExternalState(object):
    # pylint: disable=too-many-instance-attributes

    def __init__(self, register_channel_for_hashlock, netting_channel):
        self.register_channel_for_hashlock = register_channel_for_hashlock
        self.netting_channel = netting_channel

        self._opened_block = netting_channel.opened()
        self._closed_block = netting_channel.closed()
        self._settled_block = netting_channel.settled()

        self.close_event = Event()
        self.settle_event = Event()

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
            raise RuntimeError(
                'channel is already open on different block prior:%s new:%s'
                % (self._opened_block, block_number)
            )

        self._opened_block = block_number

    def set_closed(self, block_number):
        if self._closed_block != 0 and self._closed_block != block_number:
            raise RuntimeError(
                'channel is already closed on different block %s %s'
                % (self._closed_block, block_number)
            )

        self._closed_block = block_number
        self.close_event.set()

    def set_settled(self, block_number):
        if self._settled_block != 0 and self._settled_block != block_number:
            raise RuntimeError(
                'channel is already settled on different block %s %s'
                % (self._settled_block, block_number)
            )

        self._settled_block = block_number
        self.settle_event.set()

    def query_settled(self):
        # FIXME: the if None: return 0 constraint should be ensured on the
        # proxy side; see also #394
        return self.netting_channel.settled() or 0

    def close(self, partner_transfer):
        return self.netting_channel.close(partner_transfer)

    def update_transfer(self, partner_transfer):
        return self.netting_channel.update_transfer(partner_transfer)

    def withdraw(self, unlock_proofs):
        return self.netting_channel.withdraw(unlock_proofs)

    def settle(self):
        return self.netting_channel.settle()


class Channel(object):
    # pylint: disable=too-many-instance-attributes,too-many-arguments,too-many-public-methods

    def __init__(
            self,
            our_state,
            partner_state,
            external_state,
            token_address,
            reveal_timeout,
            settle_timeout):

        if settle_timeout <= reveal_timeout:
            raise ValueError('reveal_timeout can not be larger-or-equal to settle_timeout')

        if reveal_timeout < 3:
            # To guarantee that tokens won't be lost the expiration needs to
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
            raise ValueError('reveal_timeout must be at least 3')

        if not isinstance(settle_timeout, (int, long)):
            raise ValueError('settle_timeout must be integral')

        if not isinstance(reveal_timeout, (int, long)):
            raise ValueError('reveal_timeout must be integral')

        self.our_state = our_state
        self.partner_state = partner_state

        self.channel_address = external_state.netting_channel.address
        self.token_address = token_address
        self.reveal_timeout = reveal_timeout
        self.settle_timeout = settle_timeout
        self.external_state = external_state

        self.received_transfers = list()
        self.sent_transfers = list()

    @property
    def state(self):
        if self.external_state.settled_block != 0:
            return CHANNEL_STATE_SETTLED

        if self.external_state.closed_block != 0:
            return CHANNEL_STATE_CLOSED

        if self.external_state.opened_block != 0:
            return CHANNEL_STATE_OPENED

        # waiting for the first deposit
        return CHANNEL_STATE_INITIALIZING

    @property
    def our_address(self):
        return self.our_state.address

    @property
    def partner_address(self):
        return self.partner_state.address

    @property
    def can_transfer(self):
        return (
            self.state == CHANNEL_STATE_OPENED and
            self.distributable > 0
        )

    @property
    def contract_balance(self):
        """Return the total amount of token we deposited in the channel"""
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
        """ Return the available amount of the token that our end of the
        channel can transfer to the partner.
        """
        return self.our_state.distributable(self.partner_state)

    @property
    def locked(self):
        """ Return the current amount of our token that is locked waiting for a
        secret.

        The locked value is equal to locked transfers that have been
        initialized but their secret has not being revealed.
        """
        return self.partner_state.locked()

    @property
    def outstanding(self):
        return self.our_state.locked()

    def get_settle_expiration(self, block_number):
        closed_block = self.external_state.closed_block
        if closed_block != 0:
            blocks_until_settlement = closed_block + self.settle_timeout
        else:
            blocks_until_settlement = block_number + self.settle_timeout

        return blocks_until_settlement

    def channel_closed(self, block_number):  # pylint: disable=unused-argument
        balance_proof = self.our_state.balance_proof
        transfer = balance_proof.transfer

        # the channel was closed, update our half of the state if we need to
        closing_address = self.external_state.netting_channel.closing_address()
        if closing_address != self.our_state.address:
            self.external_state.update_transfer(transfer)

        unlock_proofs = balance_proof.get_known_unlocks()
        self.external_state.withdraw(unlock_proofs)

    def get_state_for(self, node_address_bin):
        if self.our_state.address == node_address_bin:
            return self.our_state

        if self.partner_state.address == node_address_bin:
            return self.partner_state

        raise Exception('Unknown address {}'.format(encode_hex(node_address_bin)))

    def register_secret(self, secret):
        """ Register a secret.

        This wont claim the lock (update the transferred_amount), it will only
        save the secret in case that a proof needs to be created. This method
        can be used for any of the ends of the channel.

        Note:
            When a secret is revealed a message could be in-transit containing
            the older lockroot, for this reason the recipient cannot update
            their locksroot at the moment a secret was revealed.

            The protocol is to register the secret so that it can compute a
            proof of balance, if necessary, forward the secret to the sender
            and wait for the update from it. It's the sender's duty to order the
            current in-transit (and possible the transfers in queue) transfers
            and the secret/locksroot update.

            The channel and its queue must be changed in sync, a transfer must
            not be created while we update the balance_proof.

        Args:
            secret: The secret that releases a locked transfer.
        """
        hashlock = sha3(secret)

        our_known = self.our_state.balance_proof.is_known(hashlock)
        partner_known = self.partner_state.balance_proof.is_known(hashlock)

        if not our_known and not partner_known:
            msg = (
                "Secret doesn't correspond to a registered hashlock. hashlock:{} token:{}"
            ).format(
                pex(hashlock),
                pex(self.token_address),
            )

            raise ValueError(msg)

        if our_known:
            lock = self.our_state.balance_proof.get_lock_by_hashlock(hashlock)

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'SECRET REGISTERED node:%s %s > %s token:%s hashlock:%s amount:%s',
                    pex(self.our_state.address),
                    pex(self.our_state.address),
                    pex(self.partner_state.address),
                    pex(self.token_address),
                    pex(hashlock),
                    lock.amount,
                )

            self.our_state.register_secret(secret)

        if partner_known:
            lock = self.partner_state.balance_proof.get_lock_by_hashlock(hashlock)

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'SECRET REGISTERED node:%s %s > %s token:%s hashlock:%s amount:%s',
                    pex(self.our_state.address),
                    pex(self.partner_state.address),
                    pex(self.our_state.address),
                    pex(self.token_address),
                    pex(hashlock),
                    lock.amount,
                )

            self.partner_state.register_secret(secret)

    def release_lock(self, secret):
        """ Release a lock for a transfer that was initiated from this node.

        Only the sender of the mediated transfer can release a lock, the
        receiver might know the secret but it needs to wait for a message from
        the initiator. This is because the sender needs to coordinate state
        updates (the hashlock for the transfers that are in transit and/or in
        queue need to be in sync with the state known by the partner).

        Note:
            Releasing a lock should always be accompanied by at least one
            Secret message to the partner node.

            The node should also release the locks for the refund transfer.
        """
        hashlock = sha3(secret)

        if not self.partner_state.balance_proof.is_known(hashlock):
            msg = "The secret doesn't unlock any hashlock. hashlock:{} token:{}".format(
                pex(hashlock),
                pex(self.token_address),
            )

            raise ValueError(msg)

        lock = self.partner_state.balance_proof.get_lock_by_hashlock(hashlock)

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'TOKEN UNLOCKED %s > %s token:%s hashlock:%s lockhash:%s amount:%s',
                pex(self.our_state.address),
                pex(self.partner_state.address),
                pex(self.token_address),
                pex(hashlock),
                pex(sha3(lock.as_bytes)),
                lock.amount,
            )

        self.partner_state.release_lock(self.our_state, secret)

    def withdraw_lock(self, secret):
        """ A lock was released by the sender, withdraw its funds and update
        the state.
        """
        hashlock = sha3(secret)

        if not self.our_state.balance_proof.is_known(hashlock):
            msg = "The secret doesn't withdraw any hashlock. hashlock:{} token:{}".format(
                pex(hashlock),
                pex(self.token_address),
            )
            raise ValueError(msg)

        lock = self.our_state.balance_proof.get_lock_by_hashlock(hashlock)

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'TOKEN WITHDRAWN %s < %s token:%s hashlock:%s lockhash:%s amount:%s',
                pex(self.our_state.address),
                pex(self.partner_state.address),
                pex(self.token_address),
                pex(hashlock),
                pex(sha3(lock.as_bytes)),
                lock.amount,
            )

        self.our_state.release_lock(self.partner_state, secret)

    def register_transfer(self, block_number, transfer):
        """ Register a signed transfer, updating the channel's state accordingly. """

        if transfer.recipient == self.partner_state.address:
            self.register_transfer_from_to(
                block_number,
                transfer,
                from_state=self.our_state,
                to_state=self.partner_state,
            )

            self.sent_transfers.append(transfer)

        elif transfer.recipient == self.our_state.address:
            self.register_transfer_from_to(
                block_number,
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

    def register_transfer_from_to(
            self,
            block_number,
            transfer,
            from_state,
            to_state):  # noqa pylint: disable=too-many-branches,too-many-statements

        """ Validates and register a signed transfer, updating the channel's state accordingly.

        Note:
            The transfer must be registered before it is sent, not on
            acknowledgement. That is necessary for two reasons:

            - Guarantee that the transfer is valid.
            - Avoid sending a new transaction without funds.

        Raises:
            InsufficientBalance: If the transfer is negative or above the distributable amount.
            InvalidLocksRoot: If locksroot check fails.
            InvalidNonce: If the expected nonce does not match.
            ValueError: If there is an address mismatch (token or node address).
        """
        if transfer.token != self.token_address:
            raise ValueError('Token address mismatch')

        if transfer.recipient != to_state.address:
            raise ValueError('Unknown recipient')

        if transfer.sender != from_state.address:
            raise ValueError('Unsigned transfer')

        # nonce is changed only when a transfer is un/registered, if the test
        # fails either we are out of sync, a message out of order, or it's a
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

            # For mediators: This is registering the *mediator* paying
            # transfer. The expiration of the lock must be `reveal_timeout`
            # blocks smaller than the *received* paying transfer. This cannot
            # be checked by the paying channel alone.
            #
            # For the initiators: As there is no backing transfer, the
            # expiration is arbitrary, using the channel settle_timeout as an
            # upper limit because the node receiving the transfer will use it
            # as an upper bound while mediating.
            #
            # For the receiver: A lock that expires after the settle period
            # just means there is more time to withdraw it.
            end_settle_period = self.get_settle_expiration(block_number)
            expires_after_settle = transfer.lock.expiration > end_settle_period
            is_sender = transfer.sender == self.our_address

            if is_sender and expires_after_settle:
                log.error(
                    'Lock expires after the settlement period.',
                    lock_expiration=transfer.lock.expiration,
                    current_block=block_number,
                    end_settle_period=end_settle_period,
                )

                raise ValueError('Lock expires after the settlement period.')

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
        # is changed, otherwise if a check fails and the state was changed the
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
            # be revealed through a message or a blockchain log)
            self.external_state.register_channel_for_hashlock(
                self,
                transfer.lock.hashlock,
            )

        if isinstance(transfer, DirectTransfer):
            to_state.register_direct_transfer(transfer)

        from_state.transferred_amount = transfer.transferred_amount
        from_state.nonce += 1

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
        if not self.can_transfer:
            raise ValueError('Transfer not possible, no funding or channel closed.')

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
            token=self.token_address,
            transferred_amount=transferred_amount,
            recipient=to_.address,
            locksroot=current_locksroot,
        )

    def create_lockedtransfer(self, amount, identifier, expiration, hashlock):
        """ Return a LockedTransfer message.

        This message needs to be signed and registered with the channel before sent.
        """
        if not self.can_transfer:
            raise ValueError('Transfer not possible, no funding or channel closed.')

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
            token=self.token_address,
            transferred_amount=transferred_amount,
            recipient=to_.address,
            locksroot=updated_locksroot,
            lock=lock,
        )

    def create_mediatedtransfer(
            self,
            transfer_initiator,
            transfer_target,
            fee,
            amount,
            identifier,
            expiration,
            hashlock):

        """ Return a MediatedTransfer message.

        This message needs to be signed and registered with the channel before
        sent.

        Args:
            transfer_initiator (address): The node that requested the transfer.
            transfer_target (address): The final destination node of the transfer
            amount (float): How much of a token is being transferred.
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

    def create_refundtransfer(
            self,
            transfer_initiator,
            transfer_target,
            fee,
            amount,
            identifier,
            expiration,
            hashlock):

        locked_transfer = self.create_lockedtransfer(
            amount,
            identifier,
            expiration,
            hashlock,
        )

        refund_transfer = locked_transfer.to_refundtransfer(
            transfer_target,
            transfer_initiator,
            fee,
        )
        return refund_transfer

    def state_transition(self, state_change):
        if isinstance(state_change, Block):
            settlement_end = self.external_state.closed_block + self.settle_timeout

            if self.state == CHANNEL_STATE_CLOSED and state_change.block_number > settlement_end:
                self.external_state.settle()

        elif isinstance(state_change, ContractReceiveClosed):
            if state_change.channel_address == self.channel_address:
                self.external_state.set_closed(state_change.block_number)
                self.channel_closed(state_change.block_number)

        elif isinstance(state_change, ContractReceiveSettled):
            if state_change.channel_address == self.channel_address:
                self.external_state.set_settled(state_change.block_number)

    def serialize(self):
        return ChannelSerialization(self)

    def __eq__(self, other):
        if isinstance(other, Channel):
            return self.serialize() == other.serialize()
        return False

    def __ne__(self, other):
        return not self.__eq__(other)


class ChannelSerialization(object):

    def __init__(self, channel_instance):
        self.channel_address = channel_instance.channel_address
        self.token_address = channel_instance.token_address
        self.partner_address = channel_instance.partner_address
        self.our_address = channel_instance.our_address
        self.reveal_timeout = channel_instance.reveal_timeout

        self.our_balance_proof = channel_instance.our_state.balance_proof
        self.partner_balance_proof = channel_instance.partner_state.balance_proof

    def __eq__(self, other):
        if isinstance(other, ChannelSerialization):
            return (
                self.channel_address == other.channel_address and
                self.token_address == other.token_address and
                self.partner_address == other.partner_address and
                self.our_address == other.our_address and
                self.reveal_timeout == other.reveal_timeout and
                self.our_balance_proof == other.our_balance_proof and
                self.partner_balance_proof == other.partner_balance_proof
            )
        return False

    def __ne__(self, other):
        return not self.__eq__(other)
