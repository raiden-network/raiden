# -*- coding: utf-8 -*-
import logging

from gevent.event import Event
from ethereum import slogging
from ethereum.utils import encode_hex

from raiden.messages import (
    DirectTransfer,
    Lock,
    LockedTransfer,
    Secret,
)
from raiden.utils import sha3, pex, lpex
from raiden.exceptions import (
    AddressWithoutCode,
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
)
from raiden.transfer.mediated_transfer.state_change import (
    ContractReceiveBalance,
    ContractReceiveClosed,
    ContractReceiveSettled,
)
from raiden.transfer.merkle_tree import LEAVES, merkleroot

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class ChannelExternalState:
    # pylint: disable=too-many-instance-attributes

    def __init__(self, register_channel_for_hashlock, netting_channel):
        self.register_channel_for_hashlock = register_channel_for_hashlock
        self.netting_channel = netting_channel

        self._opened_block = netting_channel.opened()
        self._closed_block = netting_channel.closed()
        self._settled_block = 0

        assert self._opened_block, 'this value is set by the NettingChannelContract constructor'

        self.close_event = Event()
        self.settle_event = Event()

        self._called_close = False
        self._called_settle = False

    @property
    def opened_block(self):
        return self._opened_block

    @property
    def closed_block(self):
        return self._closed_block

    @property
    def settled_block(self):
        return self._settled_block

    def set_closed(self, block_number):
        if block_number <= 0:
            raise ValueError('closed block must be non-zero and positive')

        if self._closed_block != 0:
            return False

        self._closed_block = block_number
        self.close_event.set()
        return True

    def set_settled(self, block_number):
        if block_number <= 0:
            raise ValueError('settled block must be non-zero and positive')

        if self._settled_block != 0 and self._settled_block != block_number:
            return False

        self._settled_block = block_number
        self.settle_event.set()
        return True

    def close(self, balance_proof):
        if not self._called_close:
            self._called_close = True

            if balance_proof:
                nonce = balance_proof.nonce
                transferred_amount = balance_proof.transferred_amount
                locksroot = balance_proof.locksroot
                signature = balance_proof.signature
                message_hash = balance_proof.message_hash

            else:
                nonce = 0
                transferred_amount = 0
                locksroot = ''
                signature = ''
                message_hash = ''

            return self.netting_channel.close(
                nonce,
                transferred_amount,
                locksroot,
                message_hash,
                signature,
            )

    def update_transfer(self, balance_proof):
        if balance_proof:
            return self.netting_channel.update_transfer(
                balance_proof.nonce,
                balance_proof.transferred_amount,
                balance_proof.locksroot,
                balance_proof.message_hash,
                balance_proof.signature,
            )

    def withdraw(self, unlock_proofs):
        return self.netting_channel.withdraw(unlock_proofs)

    def settle(self):
        if not self._called_settle:
            self._called_settle = True
            return self.netting_channel.settle()


class Channel:
    # pylint: disable=too-many-instance-attributes,too-many-arguments,too-many-public-methods

    def __init__(
            self,
            our_state,
            partner_state,
            external_state,
            token_address,
            reveal_timeout,
            settle_timeout):

        if not isinstance(settle_timeout, int):
            raise ValueError('settle_timeout must be integral')

        if not isinstance(reveal_timeout, int):
            raise ValueError('reveal_timeout must be integral')

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

        assert self.external_state.opened_block
        return CHANNEL_STATE_OPENED

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
        return (
            self.our_state.contract_balance -
            self.our_state.transferred_amount +
            self.partner_state.transferred_amount
        )

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
        return self.our_state.amount_locked

    @property
    def outstanding(self):
        return self.partner_state.amount_locked

    def get_settle_expiration(self, block_number):
        closed_block = self.external_state.closed_block
        if closed_block != 0:
            blocks_until_settlement = closed_block + self.settle_timeout
        else:
            blocks_until_settlement = block_number + self.settle_timeout

        return blocks_until_settlement

    def handle_closed(self, block_number, closing_address):  # pylint: disable=unused-argument
        balance_proof = self.partner_state.balance_proof

        # the channel was closed, update our half of the state if we need to
        if closing_address != self.our_state.address:
            self.external_state.update_transfer(balance_proof)

        unlock_proofs = self.partner_state.get_known_unlocks()

        try:
            self.external_state.withdraw(unlock_proofs)
        except AddressWithoutCode:
            log.error('withdraw failed, channel is gone.')

    def handle_settled(self, block_number):  # pylint: disable=unused-argument
        pass

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

        our_known = self.our_state.is_known(hashlock)
        partner_known = self.partner_state.is_known(hashlock)

        if not our_known and not partner_known:
            msg = (
                "Secret doesn't correspond to a registered hashlock. hashlock:{} token:{}"
            ).format(
                pex(hashlock),
                pex(self.token_address),
            )

            raise ValueError(msg)

        if our_known:
            lock = self.our_state.get_lock_by_hashlock(hashlock)

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'SECRET REGISTERED',
                    node=pex(self.our_state.address),
                    from_=pex(self.our_state.address),
                    to=pex(self.partner_state.address),
                    token=pex(self.token_address),
                    hashlock=pex(hashlock),
                    amount=lock.amount,
                )

            self.our_state.register_secret(secret)

        if partner_known:
            lock = self.partner_state.get_lock_by_hashlock(hashlock)

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'SECRET REGISTERED',
                    node=pex(self.our_state.address),
                    from_=pex(self.partner_state.address),
                    to=pex(self.our_state.address),
                    token=pex(self.token_address),
                    hashlock=pex(hashlock),
                    amount=lock.amount,
                )

            self.partner_state.register_secret(secret)

    def register_transfer(self, block_number, transfer):
        """ Register a signed transfer, updating the channel's state accordingly. """

        if transfer.sender == self.our_state.address:
            self.register_transfer_from_to(
                block_number,
                transfer,
                from_state=self.our_state,
                to_state=self.partner_state,
            )

            self.sent_transfers.append(transfer)

        elif transfer.sender == self.partner_state.address:
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
                    'Received a transfer from party that is not a part of the channel',
                    node=self.our_state.address,
                    from_=pex(transfer.sender),
                    channel=pex(transfer.channel)
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
        if transfer.channel != self.channel_address:
            raise ValueError('Channel address mismatch')

        if transfer.sender != from_state.address:
            raise ValueError('Unsigned transfer')

        # nonce is changed only when a transfer is un/registered, if the test
        # fails either we are out of sync, a message out of order, or it's a
        # forged transfer
        is_invalid_nonce = (
            transfer.nonce < 1 or
            (
                from_state.nonce is not None and
                transfer.nonce != from_state.nonce + 1
            )
        )
        if is_invalid_nonce:
            # this may occur on normal operation
            if log.isEnabledFor(logging.INFO):
                log.info(
                    'INVALID NONCE',
                    node=pex(self.our_address),
                    from_=pex(transfer.sender),
                    to=pex(to_state.address),

                    expected_nonce=from_state.nonce,
                    nonce=transfer.nonce,
                )
            raise InvalidNonce(transfer)

        # if the locksroot is out-of-sync (because a transfer was created while
        # a Secret was in traffic) the balance _will_ be wrong, so first check
        # the locksroot and then the balance
        if isinstance(transfer, LockedTransfer):
            if from_state.is_known(transfer.lock.hashlock):
                # this may occur on normal operation
                if log.isEnabledFor(logging.INFO):
                    lockhashes = list(from_state.hashlocks_to_unclaimedlocks.values())
                    lockhashes.extend(from_state.hashlocks_to_pendinglocks.values())
                    log.info(
                        'duplicated lock',
                        node=pex(self.our_address),
                        from_=pex(from_state.address),
                        to=pex(to_state.address),
                        hashlock=pex(transfer.lock.hashlock),
                        lockhash=pex(sha3(transfer.lock.as_bytes)),
                        lockhashes=lpex(str(l).encode() for l in lockhashes),
                        received_locksroot=pex(transfer.locksroot),
                    )
                raise ValueError('hashlock is already registered')

            # As a receiver: Check that all locked transfers are registered in
            # the locksroot, if any hashlock is missing there is no way to
            # claim it while the channel is closing
            expected_locksroot = from_state.compute_merkleroot_with(transfer.lock)
            if expected_locksroot != transfer.locksroot:
                # this should not happen
                if log.isEnabledFor(logging.WARN):
                    lockhashes = list(from_state.hashlocks_to_unclaimedlocks.values())
                    lockhashes.extend(from_state.hashlocks_to_pendinglocks.values())
                    log.warn(
                        'LOCKSROOT MISMATCH',
                        node=pex(self.our_address),
                        from_=pex(from_state.address),
                        to=pex(to_state.address),
                        lockhash=pex(sha3(transfer.lock.as_bytes)),
                        lockhashes=lpex(str(l).encode() for l in lockhashes),
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
                if log.isEnabledFor(logging.ERROR):
                    log.error(
                        'Lock expires after the settlement period.',
                        node=pex(self.our_address),
                        from_=pex(from_state.address),
                        to=pex(to_state.address),
                        lock_expiration=transfer.lock.expiration,
                        current_block=block_number,
                        end_settle_period=end_settle_period,
                    )

                raise ValueError('Lock expires after the settlement period.')

        # only check the balance if the locksroot matched
        if transfer.transferred_amount < from_state.transferred_amount:
            if log.isEnabledFor(logging.ERROR):
                log.error(
                    'NEGATIVE TRANSFER',
                    node=pex(self.our_state.address),
                    from_=pex(from_state.address),
                    to=pex(to_state.address),
                    transfer=transfer,
                )

            raise ValueError('Negative transfer')

        amount = transfer.transferred_amount - from_state.transferred_amount
        distributable = from_state.distributable(to_state)

        if isinstance(transfer, DirectTransfer):
            if amount > distributable:
                raise InsufficientBalance(transfer)

        elif isinstance(transfer, LockedTransfer):
            if amount + transfer.lock.amount > distributable:
                raise InsufficientBalance(transfer)

        elif isinstance(transfer, Secret):
            hashlock = sha3(transfer.secret)
            lock = from_state.get_lock_by_hashlock(hashlock)
            transferred_amount = from_state.transferred_amount + lock.amount

            # transfer.transferred_amount could be larger than the previous
            # transferred_amount + lock.amount, that scenario is a bug of the
            # payer
            if transfer.transferred_amount != transferred_amount:
                raise ValueError(
                    'invalid transferred_amount, expected: {} got: {}'.format(
                        transferred_amount,
                        transfer.transferred_amount,
                    )
                )

        # all checks need to be done before the internal state of the channel
        # is changed, otherwise if a check fails and the state was changed the
        # channel will be left trashed

        if isinstance(transfer, LockedTransfer):
            if log.isEnabledFor(logging.DEBUG):
                lockhashes = list(from_state.hashlocks_to_unclaimedlocks.values())
                lockhashes.extend(from_state.hashlocks_to_pendinglocks.values())
                log.debug(
                    'REGISTERED LOCK',
                    node=pex(self.our_state.address),
                    from_=pex(from_state.address),
                    to=pex(to_state.address),
                    currentlocksroot=pex(merkleroot(from_state.merkletree)),
                    lockhashes=lpex(str(l).encode() for l in lockhashes),
                    lock_amount=transfer.lock.amount,
                    lock_expiration=transfer.lock.expiration,
                    lock_hashlock=pex(transfer.lock.hashlock),
                    lockhash=pex(sha3(transfer.lock.as_bytes)),
                )

            from_state.register_locked_transfer(transfer)

            # register this channel as waiting for the secret (the secret can
            # be revealed through a message or a blockchain log)
            self.external_state.register_channel_for_hashlock(
                self,
                transfer.lock.hashlock,
            )

        if isinstance(transfer, DirectTransfer):
            from_state.register_direct_transfer(transfer)

        elif isinstance(transfer, Secret):
            from_state.register_secretmessage(transfer)

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'REGISTERED TRANSFER',
                node=pex(self.our_state.address),
                from_=pex(from_state.address),
                to=pex(to_state.address),
                transfer=repr(transfer),
                transferred_amount=from_state.transferred_amount,
                nonce=from_state.nonce,
                current_locksroot=pex(merkleroot(from_state.merkletree)),
            )

    def get_next_nonce(self):
        if self.our_state.nonce:
            return self.our_state.nonce + 1

        # 0 must not be used since in the netting contract it represents null.
        return 1

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
        current_locksroot = merkleroot(to_.merkletree)

        nonce = self.get_next_nonce()

        return DirectTransfer(
            identifier=identifier,
            nonce=nonce,
            token=self.token_address,
            channel=self.channel_address,
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

        if amount <= 0 or amount > self.distributable:
            log.debug(
                'Insufficient funds',
                amount=amount,
                distributable=self.distributable,
            )
            raise ValueError('Insufficient funds')

        from_ = self.our_state
        to_ = self.partner_state

        lock = Lock(amount, expiration, hashlock)

        updated_locksroot = from_.compute_merkleroot_with(include=lock)
        transferred_amount = from_.transferred_amount
        nonce = self.get_next_nonce()

        return LockedTransfer(
            identifier=identifier,
            nonce=nonce,
            token=self.token_address,
            channel=self.channel_address,
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

    def create_secret(self, identifier, secret):
        hashlock = sha3(secret)

        from_ = self.our_state

        lock = from_.get_lock_by_hashlock(hashlock)
        locksroot_with_pending_lock_removed = from_.compute_merkleroot_without(lock)
        transferred_amount = from_.transferred_amount + lock.amount

        nonce = self.get_next_nonce()

        secret = Secret(
            identifier,
            nonce,
            self.channel_address,
            transferred_amount,
            locksroot_with_pending_lock_removed,
            secret,
        )
        return secret

    def state_transition(self, state_change):
        if isinstance(state_change, Block):

            if self.state == CHANNEL_STATE_CLOSED:
                settlement_end = self.external_state.closed_block + self.settle_timeout

                if state_change.block_number > settlement_end:
                    self.external_state.settle()

        elif isinstance(state_change, ContractReceiveClosed):
            if state_change.channel_address == self.channel_address:
                if self.external_state.set_closed(state_change.block_number):
                    self.handle_closed(
                        state_change.block_number,
                        state_change.closing_address,
                    )
                else:
                    log.warn(
                        'channel closed on a different block or close event happened twice',
                        channel_address=pex(self.channel_address),
                        closed_block=self.external_state.closed_block,
                        this_block=state_change.block_number
                    )

        elif isinstance(state_change, ContractReceiveSettled):
            if state_change.channel_address == self.channel_address:
                if self.external_state.set_settled(state_change.block_number):
                    self.handle_settled(state_change.block_number)
                else:
                    log.warn(
                        'channel is already settled on a different block',
                        channel_address=pex(self.channel_address),
                        settled_block=self.external_state.settled_block,
                        this_block=state_change.block_number
                    )

        elif isinstance(state_change, ContractReceiveBalance):
            participant_address = state_change.participant_address
            balance = state_change.balance
            channel_state = self.get_state_for(participant_address)

            if channel_state.contract_balance != balance:
                channel_state.update_contract_balance(balance)

    def serialize(self):
        return ChannelSerialization(self)

    def __eq__(self, other):
        if isinstance(other, Channel):
            return self.serialize() == other.serialize()
        return False

    def __ne__(self, other):
        return not self.__eq__(other)


class ChannelSerialization:

    def __init__(self, channel_instance):
        self.channel_address = channel_instance.channel_address
        self.token_address = channel_instance.token_address
        self.partner_address = channel_instance.partner_address
        self.our_address = channel_instance.our_address
        self.reveal_timeout = channel_instance.reveal_timeout

        self.our_balance_proof = channel_instance.our_state.balance_proof
        self.partner_balance_proof = channel_instance.partner_state.balance_proof
        self.our_leaves = channel_instance.our_state.merkletree.layers[LEAVES]
        self.partner_leaves = channel_instance.our_state.merkletree.layers[LEAVES]

    def __eq__(self, other):
        if isinstance(other, ChannelSerialization):
            return (
                self.channel_address == other.channel_address and
                self.token_address == other.token_address and
                self.partner_address == other.partner_address and
                self.our_address == other.our_address and
                self.reveal_timeout == other.reveal_timeout and
                self.our_balance_proof == other.our_balance_proof and
                self.partner_balance_proof == other.partner_balance_proof and
                self.our_leaves == other.our_leaves and
                self.partner_leaves == other.partner_leaves
            )
        return False

    def __ne__(self, other):
        return not self.__eq__(other)
