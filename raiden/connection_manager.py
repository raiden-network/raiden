# -*- coding: utf-8 -*-
import time

from gevent.lock import Semaphore

from ethereum import slogging
from raiden.utils import pex
from raiden.channel import CHANNEL_STATE_SETTLED

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


class ConnectionManager(object):
    """
    The ConnectionManager provides a high level abstraction for connecting to a
    Token network.
    Note:
        It is initialized with 0 funds; a connection to the token network
        will be only established _after_ calling `connect(funds)`
    """
    # XXX Hack: for bootstrapping the first node on a network opens a channel
    # with this address to become visible.
    BOOTSTRAP_ADDR_HEX = '2' * 40
    BOOTSTRAP_ADDR = BOOTSTRAP_ADDR_HEX.decode('hex')

    def __init__(
        self,
        raiden,
        token_address,
        initial_channel_target=3,  # number of channels to open immediately
        joinable_funds_target=.4,  # amount of funds not initially assigned
    ):
        self.lock = Semaphore()
        self.funds = 0
        self.raiden = raiden
        self.token_address = token_address
        self.initial_channel_target = initial_channel_target
        self.joinable_funds_target = joinable_funds_target
        # force state update
        self.raiden.poll_blockchain_events(self.raiden.get_block_number())
        if self.token_address in self.raiden.channelgraphs.keys():
            self.channelgraph = self.raiden.channelgraphs[self.token_address]
            if len(self.channelgraph.graph.nodes()) == 0:
                log.debug('BOOTSTRAP for existing token')
                # make ourselves visible
                self.raiden.api.open(
                    self.token_address,
                    ConnectionManager.BOOTSTRAP_ADDR
                )
        else:
            log.debug(
                'token not yet registered',
                token=pex(self.token_address)
            )
            self.raiden.chain.default_registry.add_token(self.token_address)
            # force state update
            self.raiden.poll_blockchain_events(self.raiden.get_block_number())
            self.channelgraph = self.raiden.channelgraphs[self.token_address]
            # make ourselves visible
            self.raiden.api.open(
                self.token_address,
                ConnectionManager.BOOTSTRAP_ADDR
            )

    def connect(self, funds):
        """Connect to the network.
        Use this to establish a connection with the token network.
        Args:
            funds (int): the amount of tokens spendable for this
                         ConnectionManager.
        """
        if funds <= 0:
            raise ValueError('connecting needs a positive value for `funds`')
        with self.lock:
            self.funds = funds
            funding = self.initial_funding_per_partner
            for partner in self.find_new_partners(self.initial_channel_target):
                self.raiden.api.open(
                    self.token_address,
                    partner,
                )
                self.raiden.api.deposit(
                    self.token_address,
                    partner,
                    funding
                )

    def leave(self, wait_for_settle=True, max_wait=30):
        """
        Leave the token network.
        This implies closing all open channels and optionally wait for
        settlement.
        Args:
            wait_for_settle (bool): block until successful settlement?
            max_wait (float): maximum time to wait
        """
        with self.lock:
            self.initial_channel_target = 0
            open_channels = self.open_channels
            channel_specs = [(
                self.token_address,
                c.partner_address) for c in open_channels]
            for channel in channel_specs:
                try:
                    self.raiden.api.close(*channel),
                except RuntimeError:
                    # if the error wasn't that the channel was already closed: raise
                    if channel[1] in [c.partner_address for c in self.open_channels]:
                        raise

            # force state update
            self.raiden.poll_blockchain_events(self.raiden.get_block_number())

            if wait_for_settle:
                timeout = time.time() + max_wait
                while any(c.state != CHANNEL_STATE_SETTLED for c in open_channels):
                    # force state update
                    self.raiden.poll_blockchain_events(self.raiden.get_block_number())
                    if time.time() > timeout:
                        log.debug(
                            'timeout while waiting for settlement',
                            unsettled=sum(
                                1 for channel in open_channels if
                                channel.state != CHANNEL_STATE_SETTLED
                            ),
                            settled=sum(
                                1 for channel in open_channels if
                                channel.state == CHANNEL_STATE_SETTLED
                            )
                        )
                        break

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
        if self.initial_channel_target < 1:
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

            self.raiden.api.deposit(
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
        if self.initial_channel_target == 0:
            return
        with self.lock:
            if self.funds_remaining <= 0:
                return
            if len(self.open_channels) >= self.initial_channel_target:
                return
            for partner in self.find_new_partners(
                self.initial_channel_target - len(self.open_channels)
            ):
                try:
                    self.raiden.api.open(
                        self.token_address,
                        partner
                    )
                    self.raiden.api.deposit(
                        self.token_address,
                        partner,
                        self.initial_funding_per_partner
                    )
                # this can fail because of a race condition, where the channel partner opens first
                except Exception as e:
                    log.error('could not open a channel', exc_info=e)

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
        return (
            self.funds_remaining > 0 and
            len(self.open_channels) < self.initial_channel_target
        )

    @property
    def funds_remaining(self):
        """The remaining funds after subtracting the already deposited amounts.
        """
        if self.funds > 0:
            remaining = self.funds - sum(
                channel.deposit for channel in self.open_channels
            )
            assert isinstance(remaining, int)
            return remaining
        return 0

    @property
    def open_channels(self):
        """Shorthand for getting our open channels in this token network.
        """
        return [
            channel for channel in
            self.raiden.api.get_channel_list(token_address=self.token_address)
            if channel.isopen
        ]
