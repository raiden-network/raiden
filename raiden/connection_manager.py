# -*- coding: utf-8 -*-
from binascii import unhexlify

import gevent
from gevent.lock import Semaphore
from gevent.event import AsyncResult

from ethereum import slogging

from raiden.exceptions import DuplicatedChannelError
from raiden.api.python import RaidenAPI
from raiden.utils import pex
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLED,
)
from raiden.exceptions import (
    AddressWithoutCode,
    TransactionThrew,
)

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


class ConnectionManager:
    """The ConnectionManager provides a high level abstraction for connecting to a
    Token network.

    Note:
        It is initialized with 0 funds; a connection to the token network
        will be only established _after_ calling `connect(funds)`
    """
    # XXX Hack: for bootstrapping, the first node on a network opens a channel
    # with this address to become visible.
    BOOTSTRAP_ADDR_HEX = b'2' * 40
    BOOTSTRAP_ADDR = unhexlify(BOOTSTRAP_ADDR_HEX)

    def __init__(
            self,
            raiden,
            token_address,
            channelgraph):
        self.lock = Semaphore()
        self.raiden = raiden
        self.api = RaidenAPI(raiden)
        self.channelgraph = channelgraph
        self.token_address = token_address
        self.funds = 0
        self.initial_channel_target = 0
        self.joinable_funds_target = 0

    def connect(
            self,
            funds,
            initial_channel_target=3,
            joinable_funds_target=.4):
        """Connect to the network.
        Use this to establish a connection with the token network.

        Subsequent calls to `connect` are allowed, but will only affect the spendable
        funds and the connection strategy parameters for the future. `connect` will not
        close any channels.

        Note: the ConnectionManager does not discriminate manually opened channels from
        automatically opened ones. If the user manually opened channels, those deposit
        amounts will affect the funding per channel and the number of new channels opened.

        Args:
            funds (int): the amount of tokens spendable for this
            ConnectionManager.
            initial_channel_target (int): number of channels to open immediately
            joinable_funds_target (float): amount of funds not initially assigned
        """
        if funds <= 0:
            raise ValueError('connecting needs a positive value for `funds`')

        if self.token_address in self.raiden.message_handler.blocked_tokens:
            self.raiden.message_handler.blocked_tokens.pop(self.token_address)

        self.initial_channel_target = initial_channel_target
        self.joinable_funds_target = joinable_funds_target

        open_channels = self.open_channels
        # there are already channels open
        if len(open_channels):
            log.debug(
                'connect() called on an already joined token network',
                token_address=pex(self.token_address),
                open_channels=len(open_channels),
                sum_deposits=self.sum_deposits,
                funds=funds,
            )

        if len(self.channelgraph.graph.nodes()) == 0:
            with self.lock:
                log.debug('bootstrapping token network.')
                # make ourselves visible
                self.api.open(
                    self.token_address,
                    ConnectionManager.BOOTSTRAP_ADDR
                )

        with self.lock:
            # set our available funds
            self.funds = funds
            # try to fullfill our connection goal
            self._add_new_partners()

    def leave_async(self):
        """ Async version of `leave()`
        """
        leave_result = AsyncResult()
        gevent.spawn(self.leave).link(leave_result)
        return leave_result

    def leave(self, only_receiving=True):
        """ Leave the token network.
        This implies closing all channels and waiting for all channels to be settled.
        """
        # set leaving state
        if self.token_address not in self.raiden.message_handler.blocked_tokens:
            self.raiden.message_handler.blocked_tokens.append(self.token_address)
        if self.initial_channel_target > 0:
            self.initial_channel_target = 0

        closed_channels = self.close_all(only_receiving)
        self.wait_for_settle(closed_channels)
        return closed_channels

    def close_all(self, only_receiving=True):
        """ Close all channels in the token network.
        Note: By default we're just discarding all channels we haven't received anything.
        This potentially leaves deposits locked in channels after `closing`. This is "safe"
        from an accounting point of view (deposits can not be lost), but may still be
        undesirable from a liquidity point of view (deposits will only be freed after
        manually closing or after the partner closed the channel).

        If only_receiving is False then we close and settle all channels irrespective of them
        having received transfers or not.
        """
        with self.lock:
            self.initial_channel_target = 0
            channels_to_close = (
                self.receiving_channels[:] if only_receiving else self.open_channels[:]
            )
            for channel in channels_to_close:
                # FIXME: race condition, this can fail if channel was closed externally
                self.api.close(self.token_address, channel.partner_address)
            return channels_to_close

    def wait_for_settle(self, closed_channels):
        """Wait for all closed channels of the token network to settle.
        Note, that this does not time out.
        """
        not_settled_channels = [
            channel for channel in closed_channels
            if not channel.state != CHANNEL_STATE_SETTLED
        ]
        while any(c.state != CHANNEL_STATE_SETTLED for c in not_settled_channels):
            # wait for events to propagate
            gevent.sleep(self.raiden.alarm.wait_time)
        return True

    def join_channel(self, partner_address, partner_deposit):
        """Will be called, when we were selected as channel partner by another
        node. It will fund the channel with up to the partner's deposit, but
        not more than remaining funds or the initial funding per channel.

        If the connection manager has no funds, this is a noop.
        """
        # not initialized
        if self.funds <= 0:
            return
        # in leaving state
        if self.leaving_state:
            return
        with self.lock:
            remaining = self.funds_remaining
            initial = self.initial_funding_per_partner
            joining_funds = min(
                partner_deposit,
                remaining,
                initial
            )
            if joining_funds <= 0:
                return

            self.api.deposit(
                self.token_address,
                partner_address,
                joining_funds
            )
            log.debug(
                'joined a channel!',
                funds=joining_funds,
                me=pex(self.raiden.address),
                partner=pex(partner_address)
            )

    def retry_connect(self):
        """Will be called when new channels in the token network are detected.
        If the minimum number of channels was not yet established, it will try
        to open new channels.

        If the connection manager has no funds, this is a noop.
        """
        # not initialized
        if self.funds <= 0:
            return
        # in leaving state
        if self.leaving_state:
            return
        with self.lock:
            if self.funds_remaining <= 0:
                return
            if len(self.open_channels) >= self.initial_channel_target:
                return

            # try to fullfill our connection goal
            self._add_new_partners()

    def _add_new_partners(self):
        """ This opens channels with a number of new partners according to the
        connection strategy parameter `self.initial_channel_target`.
        Each new channel will receive `self.initial_funding_per_partner` funding. """
        # this could be a subsequent call, or some channels already open
        new_partner_count = max(
            0,
            self.initial_channel_target - len(self.open_channels)
        )
        for partner in self.find_new_partners(new_partner_count):
            self._open_and_deposit(partner, self.initial_funding_per_partner)

    def _open_and_deposit(self, partner, funding_amount):
        """ Open a channel with `partner` and deposit `funding_amount` tokens.

        If the channel was already opened (a known race condition),
        this skips the opening and only deposits.
        """
        try:
            self.api.open(
                self.token_address,
                partner
            )
        # this can fail because of a race condition, where the channel partner opens first
        except DuplicatedChannelError:
            log.info('partner opened channel first')

        channelgraph = self.raiden.token_to_channelgraph[self.token_address]
        if partner not in channelgraph.partneraddress_to_channel:
            self.raiden.poll_blockchain_events()

        if partner not in channelgraph.partneraddress_to_channel:
            log.error(
                'Opening new channel failed; channel already opened, '
                'but partner not in channelgraph',
                partner=pex(partner),
                token_address=pex(self.token_address),
            )
        else:
            try:
                self.api.deposit(
                    self.token_address,
                    partner,
                    funding_amount,
                )
            except AddressWithoutCode:
                log.warn('connection manager: channel closed just after it was created')
            except TransactionThrew:
                log.exception('connection manager: deposit failed')

    def find_new_partners(self, number):
        """Search the token network for potential channel partners.

        Args:
            number (int): number of partners to return
        """
        known = set(c.partner_address for c in self.open_channels)
        known = known.union({self.__class__.BOOTSTRAP_ADDR})
        known = known.union({self.raiden.address})
        available = set(self.channelgraph.graph.nodes()) - known

        available = self._select_best_partners(available)
        log.debug('found {} partners'.format(len(available)))
        return available[:number]

    def _select_best_partners(self, partners):
        # FIXME: use a proper selection strategy
        # https://github.com/raiden-network/raiden/issues/576
        return list(partners)

    @property
    def initial_funding_per_partner(self):
        """The calculated funding per partner depending on configuration and
        overall funding of the ConnectionManager.
        """
        if self.initial_channel_target:
            return int(
                self.funds * (1 - self.joinable_funds_target) /
                self.initial_channel_target
            )
        else:
            return 0

    @property
    def wants_more_channels(self):
        """True, if funds available and the `initial_channel_target` was not yet
        reached.
        """
        if self.token_address in self.raiden.message_handler.blocked_tokens:
            return False
        return (
            self.funds_remaining > 0 and
            len(self.open_channels) < self.initial_channel_target
        )

    @property
    def funds_remaining(self):
        """The remaining funds after subtracting the already deposited amounts.
        """
        if self.funds > 0:
            remaining = self.funds - self.sum_deposits
            assert isinstance(remaining, int)
            return remaining
        return 0

    @property
    def open_channels(self):
        """Shorthand for getting our open channels in this token network.
        """
        return [
            channel for channel in
            self.api.get_channel_list(token_address=self.token_address)
            if channel.state == CHANNEL_STATE_OPENED
        ]

    @property
    def sum_deposits(self):
        """Shorthand for getting sum of all open channels deposited funds"""
        return sum(channel.contract_balance for channel in self.open_channels)

    @property
    def receiving_channels(self):
        """Shorthand for getting channels that had received any transfers in this token network.
        """
        return [
            channel for channel in self.open_channels
            if len(channel.received_transfers)
        ]

    @property
    def min_settle_blocks(self):
        """Returns the minimum necessary waiting time to settle all channels.
        """
        channels = self.receiving_channels
        timeouts = [0]
        current_block = self.raiden.get_block_number()
        for channel in channels:
            if channel.state == CHANNEL_STATE_CLOSED:
                since_closed = current_block - channel.external_state._closed_block
            elif channel.state == CHANNEL_STATE_OPENED:
                # it will at least take one more block to call close
                since_closed = -1
            else:
                since_closed = 0
            timeouts.append(channel.settle_timeout - since_closed)

        return max(timeouts)

    @property
    def leaving_state(self):
        return (
            self.token_address in self.raiden.message_handler.blocked_tokens or
            self.initial_channel_target < 1
        )
