from random import shuffle

import gevent
import structlog
from eth_utils import decode_hex
from gevent.event import AsyncResult
from gevent.lock import Semaphore

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.constants import Environment
from raiden.exceptions import (
    DepositMismatch,
    DepositOverLimit,
    DuplicatedChannelError,
    InsufficientFunds,
    InvalidAmount,
    InvalidDBData,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
    TransactionThrew,
)
from raiden.transfer import views
from raiden.utils import pex, typing
from raiden.utils.typing import Address

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name
RECOVERABLE_ERRORS = (
    DepositMismatch,
    DepositOverLimit,
    InsufficientFunds,
    RaidenRecoverableError,
    TransactionThrew,
)


def log_open_channels(raiden, registry_address, token_address, funds):
    chain_state = views.state_from_raiden(raiden)
    open_channels = views.get_channelstate_open(
        chain_state=chain_state,
        payment_network_id=registry_address,
        token_address=token_address,
    )

    if open_channels:
        sum_deposits = views.get_our_capacity_for_token_network(
            views.state_from_raiden(raiden),
            registry_address,
            token_address,
        )
        log.debug(
            'connect() called on an already joined token network',
            node=pex(raiden.address),
            registry_address=pex(registry_address),
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
    BOOTSTRAP_ADDR_HEX = '2' * 40
    BOOTSTRAP_ADDR = decode_hex(BOOTSTRAP_ADDR_HEX)

    def __init__(self, raiden, token_network_identifier):
        chain_state = views.state_from_raiden(raiden)
        token_network_state = views.get_token_network_by_identifier(
            chain_state,
            token_network_identifier,
        )
        token_network_registry = views.get_token_network_registry_by_token_network_identifier(
            chain_state,
            token_network_identifier,
        )

        # TODO:
        # - Add timeout for transaction polling, used to overwrite the RaidenAPI
        # defaults
        # - Add a proper selection strategy (#576)
        self.funds = 0
        self.initial_channel_target = 0
        self.joinable_funds_target = 0

        self.raiden = raiden
        self.registry_address = token_network_registry.address
        self.token_network_identifier = token_network_identifier
        self.token_address = token_network_state.token_address

        self.lock = Semaphore()  #: protects self.funds and self.initial_channel_target
        self.api = RaidenAPI(raiden)

    def connect(
            self,
            funds: typing.TokenAmount,
            initial_channel_target: int = 3,
            joinable_funds_target: float = 0.4,
    ):
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
        token = self.raiden.chain.token(self.token_address)
        token_balance = token.balance_of(self.raiden.address)

        if token_balance < funds:
            raise InvalidAmount(
                f'Insufficient balance for token {pex(self.token_address)}',
            )

        if funds <= 0:
            raise InvalidAmount(
                'The funds to use in the connection need to be a positive integer',
            )

        if joinable_funds_target < 0 or joinable_funds_target > 1:
            raise InvalidAmount(
                f'joinable_funds_target should be between 0 and 1. Given: {joinable_funds_target}',
            )

        with self.lock:
            self.funds = funds
            self.initial_channel_target = initial_channel_target
            self.joinable_funds_target = joinable_funds_target

            log_open_channels(self.raiden, self.registry_address, self.token_address, funds)

            qty_network_channels = views.count_token_network_channels(
                views.state_from_raiden(self.raiden),
                self.registry_address,
                self.token_address,
            )

            if not qty_network_channels:
                log.info(
                    'Bootstrapping token network.',
                    node=pex(self.raiden.address),
                    network_id=pex(self.registry_address),
                    token_id=pex(self.token_address),
                )
                self.api.channel_open(
                    self.registry_address,
                    self.token_address,
                    self.BOOTSTRAP_ADDR,
                )
            else:
                self._open_channels()

    def leave_async(self):
        """ Async version of `leave()` """
        leave_result = AsyncResult()
        gevent.spawn(self.leave).link(leave_result)
        return leave_result

    def leave(self, registry_address):
        """ Leave the token network.

        This implies closing all channels and waiting for all channels to be
        settled.
        """
        with self.lock:
            self.initial_channel_target = 0

            channels_to_close = views.get_channelstate_open(
                chain_state=views.state_from_raiden(self.raiden),
                payment_network_id=registry_address,
                token_address=self.token_address,
            )

            partner_addresses = [
                channel_state.partner_state.address
                for channel_state in channels_to_close
            ]
            self.api.channel_batch_close(
                registry_address,
                self.token_address,
                partner_addresses,
            )

            channel_ids = [
                channel_state.identifier
                for channel_state in channels_to_close
            ]

            waiting.wait_for_settle(
                self.raiden,
                registry_address,
                self.token_address,
                channel_ids,
                self.raiden.alarm.sleep_time,
            )

        return channels_to_close

    def join_channel(self, partner_address, partner_deposit):
        """Will be called, when we were selected as channel partner by another
        node. It will fund the channel with up to the partners deposit, but
        not more than remaining funds or the initial funding per channel.

        If the connection manager has no funds, this is a noop.
        """

        # Consider this race condition:
        #
        # - Partner opens the channel and starts the deposit.
        # - This nodes learns about the new channel, starts ConnectionManager's
        #   retry_connect, which will start a deposit for this half of the
        #   channel.
        # - This node learns about the partner's deposit before its own.
        #   join_channel is called which will try to deposit again.
        #
        # To fix this race, first the node must wait for the pending operations
        # to finish, because in them could be a deposit, and then deposit must
        # be called only if the channel is still not funded.
        token_network_proxy = self.raiden.chain.token_network(self.token_network_identifier)

        # Wait for any pending operation in the channel to complete, before
        # deciding on the deposit
        with self.lock, token_network_proxy.channel_operations_lock[partner_address]:
            channel_state = views.get_channelstate_for(
                views.state_from_raiden(self.raiden),
                self.token_network_identifier,
                self.token_address,
                partner_address,
            )

            if not channel_state:
                return

            joining_funds = min(
                partner_deposit,
                self._funds_remaining,
                self._initial_funding_per_partner,
            )
            if joining_funds <= 0 or self._leaving_state:
                return

            if joining_funds <= channel_state.our_state.contract_balance:
                return

            try:
                self.api.set_total_channel_deposit(
                    self.registry_address,
                    self.token_address,
                    partner_address,
                    joining_funds,
                )
            except RaidenRecoverableError:
                log.info(
                    'Channel not in opened state',
                    node=pex(self.raiden.address),
                )
            except InvalidDBData:
                raise
            except RaidenUnrecoverableError as e:
                should_crash = (
                    self.raiden.config['environment_type'] != Environment.PRODUCTION or
                    self.raiden.config['unrecoverable_error_should_crash']
                )
                if should_crash:
                    raise

                log.critical(
                    str(e),
                    node=pex(self.raiden.address),
                )
            else:
                log.info(
                    'Joined a channel',
                    node=pex(self.raiden.address),
                    partner=pex(partner_address),
                    funds=joining_funds,
                )

    def retry_connect(self):
        """Will be called when new channels in the token network are detected.
        If the minimum number of channels was not yet established, it will try
        to open new channels.

        If the connection manager has no funds, this is a noop.
        """
        with self.lock:
            if self._funds_remaining > 0 and not self._leaving_state:
                self._open_channels()

    def _find_new_partners(self):
        """ Search the token network for potential channel partners. """
        open_channels = views.get_channelstate_open(
            chain_state=views.state_from_raiden(self.raiden),
            payment_network_id=self.registry_address,
            token_address=self.token_address,
        )
        known = set(channel_state.partner_state.address for channel_state in open_channels)
        known.add(self.BOOTSTRAP_ADDR)
        known.add(self.raiden.address)

        participants_addresses = views.get_participants_addresses(
            views.state_from_raiden(self.raiden),
            self.registry_address,
            self.token_address,
        )

        available = participants_addresses - known
        available = list(available)
        shuffle(available)
        new_partners = available

        log.debug(
            'Found partners',
            node=pex(self.raiden.address),
            number_of_partners=len(available),
        )

        return new_partners

    def _join_partner(self, partner: Address):
        """ Ensure a channel exists with partner and is funded in our side """
        try:
            self.api.channel_open(
                self.registry_address,
                self.token_address,
                partner,
            )
        except DuplicatedChannelError:
            # If channel already exists (either because partner created it,
            # or it's nonfunded channel), continue to ensure it's funded
            pass

        try:
            self.api.set_total_channel_deposit(
                self.registry_address,
                self.token_address,
                partner,
                self._initial_funding_per_partner,
            )
        except InvalidDBData:
            raise
        except RECOVERABLE_ERRORS:
            log.info(
                'Deposit failed',
                node=pex(self.raiden.address),
                partner=pex(partner),
            )
        except RaidenUnrecoverableError:
            should_crash = (
                self.raiden.config['environment_type'] != Environment.PRODUCTION or
                self.raiden.config['unrecoverable_error_should_crash']
            )
            if should_crash:
                raise

            log.critical(
                'Deposit failed',
                node=pex(self.raiden.address),
                partner=pex(partner),
            )

    def _open_channels(self) -> bool:
        """ Open channels until there are `self.initial_channel_target`
        channels open. Do nothing if there are enough channels open already.

        Note:
            - This method must be called with the lock held.
        Return:
            - False if no channels could be opened
        """

        open_channels = views.get_channelstate_open(
            chain_state=views.state_from_raiden(self.raiden),
            payment_network_id=self.registry_address,
            token_address=self.token_address,
        )
        open_channels = [
            channel_state
            for channel_state in open_channels
            if channel_state.partner_state.address != self.BOOTSTRAP_ADDR
        ]
        funded_channels = [
            channel_state for channel_state in open_channels
            if channel_state.our_state.contract_balance >= self._initial_funding_per_partner
        ]
        nonfunded_channels = [
            channel_state for channel_state in open_channels
            if channel_state not in funded_channels
        ]
        possible_new_partners = self._find_new_partners()
        if possible_new_partners == 0:
            return False

        # if we already met our target, break
        if len(funded_channels) >= self.initial_channel_target:
            return False
        # if we didn't, but there's no nonfunded channels and no available partners
        # it means the network is smaller than our target, so we should also break
        if not nonfunded_channels and possible_new_partners == 0:
            return False

        n_to_join = self.initial_channel_target - len(funded_channels)
        nonfunded_partners = [
            channel_state.partner_state.address
            for channel_state in nonfunded_channels
        ]
        # first, fund nonfunded channels, then open and fund with possible_new_partners,
        # until initial_channel_target of funded channels is met
        join_partners = (nonfunded_partners + possible_new_partners)[:n_to_join]

        log.debug(
            'Spawning greenlets to join partners',
            node=pex(self.raiden.address),
            num_greenlets=len(join_partners),
        )

        greenlets = [
            gevent.spawn(self._join_partner, partner)
            for partner in join_partners
        ]
        gevent.joinall(greenlets, raise_error=True)
        return True

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
                self.initial_channel_target,
            )

        return 0

    @property
    def _funds_remaining(self) -> int:
        """The remaining funds after subtracting the already deposited amounts.

        Note:
            - This attribute must be accessed with the lock held.
        """
        if self.funds > 0:
            token = self.raiden.chain.token(self.token_address)
            token_balance = token.balance_of(self.raiden.address)
            sum_deposits = views.get_our_capacity_for_token_network(
                views.state_from_raiden(self.raiden),
                self.registry_address,
                self.token_address,
            )

            return min(self.funds - sum_deposits, token_balance)

        return 0

    @property
    def _leaving_state(self) -> bool:
        """True if the node is leaving the token network.

        Note:
            - This attribute must be accessed with the lock held.
        """
        return self.initial_channel_target < 1

    def __repr__(self) -> str:
        open_channels = views.get_channelstate_open(
            chain_state=views.state_from_raiden(self.raiden),
            payment_network_id=self.registry_address,
            token_address=self.token_address,
        )
        return f'{self.__class__.__name__}(target={self.initial_channel_target} ' +\
            f'channels={len(open_channels)}:{open_channels!r})'
