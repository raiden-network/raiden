# -*- coding: utf-8 -*-
from binascii import unhexlify

import gevent
from gevent.lock import Semaphore
from gevent.event import AsyncResult

from ethereum import slogging

from raiden import waiting
from raiden.exceptions import DuplicatedChannelError
from raiden.api.python import RaidenAPI2
from raiden.utils import pex
from raiden.exceptions import (
    AddressWithoutCode,
    TransactionThrew,
)
from raiden.transfer import views

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


def log_open_channels(raiden, token_address, funds):
    payment_network_id = raiden.default_registry.address
    open_channels = views.get_channelstate_open(
        views.state_from_raiden(raiden),
        payment_network_id,
        token_address,
    )

    if open_channels:
        sum_deposits = views.get_our_capacity_for_token_network(
            views.state_from_raiden(raiden),
            payment_network_id,
            token_address,
        )
        log.debug(
            'connect() called on an already joined token network',
            token_address=pex(token_address),
            open_channels=len(open_channels),
            sum_deposits=sum_deposits,
            funds=funds,
        )


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

    def __init__(self, raiden, token_address):
        # TODO:
        # - Add timeout for transaction polling, used to overwrite the RaidenAPI2
        # defaults
        # - Add a proper selection strategy (#576)
        self.funds = 0
        self.initial_channel_target = 0
        self.joinable_funds_target = 0

        self.raiden = raiden
        self.token_address = token_address

        self.lock = Semaphore()  #: protects self.funds and self.initial_channel_target
        self.api = RaidenAPI2(raiden)

    def connect(
            self,
            funds: int,
            initial_channel_target: int = 3,
            joinable_funds_target: float = 0.4):
        """Connect to the network.

        Subsequent calls to `connect` are allowed, but will only affect the spendable
        funds and the connection strategy parameters for the future. `connect` will not
        close any channels.

        Note: the ConnectionManager does not discriminate manually opened channels from
        automatically opened ones. If the user manually opened channels, those deposit
        amounts will affect the funding per channel and the number of new channels opened.

        Args:
            funds: Target amount of tokens spendable to join the network.
            initial_channel_target: Target number of channels to open.
            joinable_funds_target: Amount of funds not initially assigned.
        """
        if funds <= 0:
            raise ValueError('connecting needs a positive value for `funds`')

        with self.lock:
            self.funds = funds
            self.initial_channel_target = initial_channel_target
            self.joinable_funds_target = joinable_funds_target

            log_open_channels(self.raiden, self.token_address, funds)

            payment_network_id = self.raiden.default_registry.address
            qty_network_channels = views.count_token_network_channels(
                views.state_from_raiden(self.raiden),
                payment_network_id,
                self.token_address,
            )

            if not qty_network_channels:
                log.debug('bootstrapping token network.')
                # make ourselves visible
                self.api.channel_open(self.token_address, self.BOOTSTRAP_ADDR)
            else:
                self._open_channels()

    def leave_async(self, only_receiving=True):
        """ Async version of `leave()` """
        leave_result = AsyncResult()
        gevent.spawn(self.leave, only_receiving).link(leave_result)
        return leave_result

    def leave(self, only_receiving=True):
        """ Leave the token network.

        This implies closing all channels and waiting for all channels to be
        settled.

        Note: By default we're just discarding all channels for which we haven't
        received anything.  This potentially leaves deposits locked in channels after
        `closing`. This is "safe" from an accounting point of view (deposits
        can not be lost), but may still be undesirable from a liquidity point
        of view (deposits will only be freed after manually closing or after
        the partner closed the channel).

        If only_receiving is False then we close and settle all channels
        irrespective of them having received transfers or not.
        """
        with self.lock:
            self.initial_channel_target = 0
            payment_network_id = self.raiden.default_registry.address

            if only_receiving:
                channels_to_close = views.get_channestate_for_receiving(
                    views.state_from_raiden(self.raiden),
                    payment_network_id,
                    self.token_address,
                )
            else:
                channels_to_close = views.get_channelstate_open(
                    views.state_from_raiden(self.raiden),
                    payment_network_id,
                    self.token_address,
                )

            partner_addresses = [
                channel_state.partner_state.address
                for channel_state in channels_to_close
            ]
            self.api.channel_batch_close(
                self.token_address,
                partner_addresses,
            )

            channel_ids = [
                channel_state.identifier
                for channel_state in channels_to_close
            ]

            waiting.wait_for_settle(
                self.raiden,
                self.raiden.default_registry.address,
                self.token_address,
                channel_ids,
                self.raiden.alarm.wait_time,
            )

        return channels_to_close

    def join_channel(self, partner_address, partner_deposit):
        """Will be called, when we were selected as channel partner by another
        node. It will fund the channel with up to the partners deposit, but
        not more than remaining funds or the initial funding per channel.

        If the connection manager has no funds, this is a noop.
        """
        with self.lock:
            joining_funds = min(
                partner_deposit,
                self._funds_remaining,
                self._initial_funding_per_partner,
            )
            if joining_funds <= 0 or self._leaving_state:
                return

            self.api.channel_deposit(
                self.token_address,
                partner_address,
                joining_funds,
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
        with self.lock:
            if self._funds_remaining <= 0 or self._leaving_state:
                return

            payment_network_id = self.raiden.default_registry.address
            open_channels = views.get_channelstate_open(
                views.state_from_raiden(self.raiden),
                payment_network_id,
                self.token_address,
            )
            if len(open_channels) >= self.initial_channel_target:
                return

            self._open_channels()

    def find_new_partners(self, number: int):
        """Search the token network for potential channel partners.

        Args:
            number: number of partners to return
        """
        payment_network_id = self.raiden.default_registry.address
        open_channels = views.get_channelstate_open(
            views.state_from_raiden(self.raiden),
            payment_network_id,
            self.token_address,
        )
        known = set(channel_state.partner_address for channel_state in open_channels)
        known = known.add(self.BOOTSTRAP_ADDR)
        known = known.add(self.raiden.address)

        participants_addresses = views.get_participants_addresses(
            views.state_from_raiden(self.raiden),
            payment_network_id,
            self.token_address,
        )

        available = participants_addresses - known
        new_partners = list(available)[:number]

        log.debug('found {} partners'.format(len(available)))

        return new_partners

    def _open_channels(self):
        """ Open channels until there are `self.initial_channel_target`
        channels open. Do nothing if there are enough channels open already.

        Note:
            - This method must be called with the lock held.
        """
        payment_network_id = self.raiden.default_registry.address
        open_channels = views.get_channelstate_open(
            views.state_from_raiden(self.raiden),
            payment_network_id,
            self.token_address,
        )

        qty_channels_to_open = self.initial_channel_target - len(open_channels)
        if qty_channels_to_open <= 0:
            return

        for partner in self.find_new_partners(qty_channels_to_open):
            try:
                self.api.channel_open(
                    self.token_address,
                    partner
                )
            except DuplicatedChannelError:
                # This can fail because of a race condition, where the channel
                # partner opens first.
                log.info('partner opened channel first')

            try:
                self.api.channel_deposit(
                    self.token_address,
                    partner,
                    self._initial_funding_per_partner,
                )
            except AddressWithoutCode:
                log.warn('connection manager: channel closed just after it was created')
            except TransactionThrew:
                log.exception('connection manager: deposit failed')

    @property
    def _initial_funding_per_partner(self) -> int:
        """The calculated funding per partner depending on configuration and
        overall funding of the ConnectionManager.

        Note:
            - This attribute must be accessed with the lock held.
        """
        if self.initial_channel_target:
            return int(
                self.funds * (1 - self.joinable_funds_target) /
                self.initial_channel_target
            )

        return 0

    @property
    def _funds_remaining(self) -> int:
        """The remaining funds after subtracting the already deposited amounts.

        Note:
            - This attribute must be accessed with the lock held.
        """
        if self.funds > 0:
            payment_network_id = self.raiden.default_registry.address
            sum_deposits = views.get_our_capacity_for_token_network(
                views.state_from_raiden(self.raiden),
                payment_network_id,
                self.token_address,
            )

            remaining = self.funds - sum_deposits
            return remaining

        return 0

    @property
    def _leaving_state(self) -> bool:
        """True if the node is leaving the token network.

        Note:
            - This attribute must be accessed with the lock held.
        """
        return self.initial_channel_target < 1
