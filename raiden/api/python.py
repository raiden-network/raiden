# -*- coding: utf-8 -*-
from binascii import hexlify

import gevent
from gevent.event import AsyncResult
from ethereum import slogging
from ethereum.tools.tester import TransactionFailed

from raiden.blockchain.events import (
    ALL_EVENTS,
    get_all_channel_manager_events,
    get_all_registry_events,
    get_all_netting_channel_events,
)
from raiden.token_swap import (
    MakerTokenSwapTask,
    SwapKey,
    TokenSwap,
)
from raiden.transfer.events import (
    EventTransferSentSuccess,
    EventTransferSentFailed,
    EventTransferReceivedSuccess,
)
from raiden.exceptions import (
    ChannelNotFound,
    EthNodeCommunicationError,
    InsufficientFunds,
    InvalidAddress,
    InvalidAmount,
    InvalidSettleTimeout,
    InvalidState,
    NoPathError,
    NoTokenManager,
    UnknownTokenAddress,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
)
from raiden.utils import (
    isaddress,
    pex,
    wait_until,
)

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


class RaidenAPI:
    """ CLI interface. """
    # pylint: disable=too-many-public-methods

    def __init__(self, raiden):
        self.raiden = raiden

    @property
    def address(self):
        return self.raiden.address

    @property
    def tokens(self):
        """ Return a list of the tokens registered with the default registry. """
        return self.raiden.default_registry.token_addresses()

    def get_channel(self, channel_address):
        if not isaddress(channel_address):
            raise InvalidAddress('Expected binary address format for channel in get_channel')

        channel_list = self.get_channel_list()
        for channel in channel_list:
            if channel.channel_address == channel_address:
                return channel

        raise ChannelNotFound()

    def manager_address_if_token_registered(self, token_address):
        """
        If the token is registered then, return the channel manager address.
        Also make sure that the channel manager is registered with the node.

        Returns None otherwise.
        """
        if not isaddress(token_address):
            raise InvalidAddress('token_address must be a valid address in binary')

        try:
            manager = self.raiden.default_registry.manager_by_token(token_address)
            if not self.raiden.channel_manager_is_registered(manager.address):
                self.raiden.register_channel_manager(manager.address)
            return manager.address
        except (EthNodeCommunicationError, TransactionFailed, NoTokenManager):
            return None

    def register_token(self, token_address):
        """ Will register the token at `token_address` with raiden. If it's already
        registered, will throw an exception.
        """

        if not isaddress(token_address):
            raise InvalidAddress('token_address must be a valid address in binary')

        try:
            self.raiden.default_registry.manager_by_token(token_address)
        except NoTokenManager:
            channel_manager_address = self.raiden.default_registry.add_token(token_address)
            self.raiden.register_channel_manager(channel_manager_address)
            return channel_manager_address

        raise ValueError('Token already registered')

    def connect_token_network(
            self,
            token_address,
            funds,
            initial_channel_target=3,
            joinable_funds_target=.4):
        """Instruct the ConnectionManager to establish and maintain a connection to the token
        network.

        If the `token_address` is not already part of the raiden network, this will also register
        the token.

        Args:
            token_address (bin): the ERC20 token network to connect to.
            funds (int): the amount of funds that can be used by the ConnectionMananger.
            initial_channel_target (int): number of channels to open proactively.
            joinable_funds_target (float): fraction of the funds that will be used to join
                channels opened by other participants.
        """
        if not isaddress(token_address):
            raise InvalidAddress('token_address must be a valid address in binary')

        try:
            connection_manager = self.raiden.connection_manager_for_token(token_address)
        except InvalidAddress:
            # token is not yet registered
            self.raiden.default_registry.add_token(token_address)

            # wait for registration
            while token_address not in self.raiden.tokens_to_connectionmanagers:
                gevent.sleep(self.raiden.alarm.wait_time)
            connection_manager = self.raiden.connection_manager_for_token(token_address)

        connection_manager.connect(
            funds,
            initial_channel_target=initial_channel_target,
            joinable_funds_target=joinable_funds_target
        )

    def leave_token_network(self, token_address, only_receiving=True):
        """Instruct the ConnectionManager to close all channels and wait for
        settlement.
        """
        connection_manager = self.raiden.connection_manager_for_token(token_address)
        return connection_manager.leave(only_receiving)

    def get_connection_managers_info(self):
        """Get a dict whose keys are token addresses and whose values are
        open channels, funds of last request, sum of deposits and number of channels"""
        connection_managers = dict()

        for token in self.get_tokens_list():
            try:
                connection_manager = self.raiden.connection_manager_for_token(token)
            except InvalidAddress:
                connection_manager = None
            if connection_manager is not None and connection_manager.open_channels:
                connection_managers[connection_manager.token_address] = {
                    'funds': connection_manager.funds,
                    'sum_deposits': connection_manager.sum_deposits,
                    'channels': len(connection_manager.open_channels),
                }

        return connection_managers

    def open(
            self,
            token_address,
            partner_address,
            settle_timeout=None,
            reveal_timeout=None):
        """ Open a channel with the peer at `partner_address`
        with the given `token_address`.
        """
        if reveal_timeout is None:
            reveal_timeout = self.raiden.config['reveal_timeout']

        if settle_timeout is None:
            settle_timeout = self.raiden.config['settle_timeout']

        if settle_timeout <= reveal_timeout:
            raise InvalidSettleTimeout(
                'reveal_timeout can not be larger-or-equal to settle_timeout'
            )

        if not isaddress(token_address):
            raise InvalidAddress('Expected binary address format for token in channel open')

        if not isaddress(partner_address):
            raise InvalidAddress('Expected binary address format for partner in channel open')

        channel_manager = self.raiden.default_registry.manager_by_token(token_address)
        assert token_address in self.raiden.token_to_channelgraph

        netcontract_address = channel_manager.new_netting_channel(
            partner_address,
            settle_timeout,
        )
        while netcontract_address not in self.raiden.chain.address_to_nettingchannel:
            gevent.sleep(self.raiden.alarm.wait_time)

        graph = self.raiden.token_to_channelgraph[token_address]
        while partner_address not in graph.partneraddress_to_channel:
            gevent.sleep(self.raiden.alarm.wait_time)
        channel = graph.partneraddress_to_channel[partner_address]
        return channel

    def deposit(self, token_address, partner_address, amount, poll_timeout=DEFAULT_POLL_TIMEOUT):
        """ Deposit `amount` in the channel with the peer at `partner_address` and the
        given `token_address` in order to be able to do transfers.

        Raises:
            InvalidAddress: If either token_address or partner_address is not
            20 bytes long.
            TransactionThrew: May happen for multiple reasons:
                - If the token approval fails, e.g. the token may validate if
                  account has enough balance for the allowance.
                - The deposit failed, e.g. the allowance did not set the token
                  aside for use and the user spent it before deposit was called.
                - The channel was closed/settled between the allowance call and
                  the deposit call.
            AddressWithoutCode: The channel was settled during the deposit
            execution.
        """
        if not isaddress(token_address):
            raise InvalidAddress('Expected binary address format for token in channel deposit')

        if not isaddress(partner_address):
            raise InvalidAddress('Expected binary address format for partner in channel deposit')

        graph = self.raiden.token_to_channelgraph.get(token_address)
        if graph is None:
            raise InvalidAddress('Unknown token address')

        channel = graph.partneraddress_to_channel.get(partner_address)
        if channel is None:
            raise InvalidAddress('No channel with partner_address for the given token')

        if channel.token_address != token_address:
            raise InvalidAddress('token_address does not match the netting channel attribute')

        token = self.raiden.chain.token(token_address)
        netcontract_address = channel.external_state.netting_channel.address
        old_balance = channel.contract_balance

        # Checking the balance is not helpful since this requires multiple
        # transactions that can race, e.g. the deposit check succeed but the
        # user spent his balance before deposit.
        balance = token.balance_of(hexlify(self.raiden.address))
        if not balance >= amount:
            msg = 'Not enough balance to deposit. {} Available={} Tried={}'.format(
                pex(token_address),
                balance,
                amount,
            )
            raise InsufficientFunds(msg)
        token.approve(netcontract_address, amount)

        channel_proxy = self.raiden.chain.netting_channel(netcontract_address)
        channel_proxy.deposit(amount)

        # Wait until the `ChannelNewBalance` event is processed.
        #
        # Usually a single sleep is sufficient, since the `deposit` waits for
        # the transaction to be polled.
        sucess = wait_until(
            lambda: channel.contract_balance != old_balance,
            poll_timeout,
            self.raiden.alarm.wait_time,
        )

        if not sucess:
            raise EthNodeCommunicationError(
                'After {} seconds the deposit was not properly processed.'.format(
                    poll_timeout
                )
            )

        return channel

    def token_swap_and_wait(
            self,
            identifier,
            maker_token,
            maker_amount,
            maker_address,
            taker_token,
            taker_amount,
            taker_address):
        """ Start an atomic swap operation by sending a MediatedTransfer with
        `maker_amount` of `maker_token` to `taker_address`. Only proceed when a
        new valid MediatedTransfer is received with `taker_amount` of
        `taker_token`.
        """

        async_result = self.token_swap_async(
            identifier,
            maker_token,
            maker_amount,
            maker_address,
            taker_token,
            taker_amount,
            taker_address,
        )
        async_result.wait()

    def token_swap_async(
            self,
            identifier,
            maker_token,
            maker_amount,
            maker_address,
            taker_token,
            taker_amount,
            taker_address):
        """ Start a token swap operation by sending a MediatedTransfer with
        `maker_amount` of `maker_token` to `taker_address`. Only proceed when a
        new valid MediatedTransfer is received with `taker_amount` of
        `taker_token`.
        """
        if not isaddress(maker_token):
            raise InvalidAddress(
                'Address for maker token is not in expected binary format in token swap'
            )
        if not isaddress(maker_address):
            raise InvalidAddress(
                'Address for maker is not in expected binary format in token swap'
            )

        if not isaddress(taker_token):
            raise InvalidAddress(
                'Address for taker token is not in expected binary format in token swap'
            )
        if not isaddress(taker_address):
            raise InvalidAddress(
                'Address for taker is not in expected binary format in token swap'
            )

        channelgraphs = self.raiden.token_to_channelgraph

        if taker_token not in channelgraphs:
            log.error('Unknown token {}'.format(pex(taker_token)))
            return

        if maker_token not in channelgraphs:
            log.error('Unknown token {}'.format(pex(maker_token)))
            return

        token_swap = TokenSwap(
            identifier,
            maker_token,
            maker_amount,
            maker_address,
            taker_token,
            taker_amount,
            taker_address,
        )

        async_result = AsyncResult()
        task = MakerTokenSwapTask(
            self.raiden,
            token_swap,
            async_result,
        )
        task.start()

        # the maker is expecting the taker transfer
        key = SwapKey(
            identifier,
            taker_token,
            taker_amount,
        )
        self.raiden.swapkey_to_greenlettask[key] = task
        self.raiden.swapkey_to_tokenswap[key] = token_swap

        return async_result

    def expect_token_swap(
            self,
            identifier,
            maker_token,
            maker_amount,
            maker_address,
            taker_token,
            taker_amount,
            taker_address):
        """ Register an expected transfer for this node.

        If a MediatedMessage is received for the `maker_asset` with
        `maker_amount` then proceed to send a MediatedTransfer to
        `maker_address` for `taker_asset` with `taker_amount`.
        """

        if not isaddress(maker_token):
            raise InvalidAddress(
                'Address for maker token is not in expected binary format in expect_token_swap'
            )
        if not isaddress(maker_address):
            raise InvalidAddress(
                'Address for maker is not in expected binary format in expect_token_swap'
            )

        if not isaddress(taker_token):
            raise InvalidAddress(
                'Address for taker token is not in expected binary format in expect_token_swap'
            )
        if not isaddress(taker_address):
            raise InvalidAddress(
                'Address for taker is not in expected binary format in expect_token_swap'
            )

        channelgraphs = self.raiden.token_to_channelgraph

        if taker_token not in channelgraphs:
            log.error('Unknown token {}'.format(pex(taker_token)))
            return

        if maker_token not in channelgraphs:
            log.error('Unknown token {}'.format(pex(maker_token)))
            return

        # the taker is expecting the maker transfer
        key = SwapKey(
            identifier,
            maker_token,
            maker_amount,
        )

        token_swap = TokenSwap(
            identifier,
            maker_token,
            maker_amount,
            maker_address,
            taker_token,
            taker_amount,
            taker_address,
        )

        self.raiden.swapkey_to_tokenswap[key] = token_swap

    def get_channel_list(self, token_address=None, partner_address=None):
        """Returns a list of channels associated with the optionally given
           `token_address` and/or `partner_address`.

        Args:
            token_address (bin): an optionally provided token address
            partner_address (bin): an optionally provided partner address

        Return:
            A list containing all channels the node participates. Optionally
            filtered by a token address and/or partner address.

        Raises:
            KeyError: An error occurred when the token address is unknown to the node.
        """

        if token_address and not isaddress(token_address):
            raise InvalidAddress('Expected binary address format for token in get_channel_list')

        if partner_address and not isaddress(partner_address):
            raise InvalidAddress('Expected binary address format for partner in get_channel_list')

        result = list()

        if token_address and partner_address:
            graph = self.raiden.token_to_channelgraph[token_address]

            channel = graph.partneraddress_to_channel.get(partner_address)

            if channel:
                result = [channel]

        elif token_address:
            graph = self.raiden.token_to_channelgraph.get(token_address)

            if graph:
                result = list(graph.address_to_channel.values())

        elif partner_address:
            partner_channels = [
                graph.partneraddress_to_channel[partner_address]
                for graph in self.raiden.token_to_channelgraph.values()
                if partner_address in graph.partneraddress_to_channel
            ]

            result = partner_channels

        else:
            all_channels = list()
            for graph in self.raiden.token_to_channelgraph.values():
                all_channels.extend(graph.address_to_channel.values())

            result = all_channels

        return result

    def get_node_network_state(self, node_address):
        """ Returns the currently network status of `node_address`. """
        return self.raiden.protocol.nodeaddresses_networkstatuses[node_address]

    def start_health_check_for(self, node_address):
        """ Returns the currently network status of `node_address`. """
        self.raiden.start_health_check_for(node_address)
        return self.raiden.protocol.nodeaddresses_networkstatuses[node_address]

    def get_tokens_list(self):
        """Returns a list of tokens the node knows about"""
        tokens_list = list(self.raiden.token_to_channelgraph.keys())
        return tokens_list

    def transfer_and_wait(
            self,
            token_address,
            amount,
            target,
            identifier=None,
            timeout=None):
        """ Do a transfer with `target` with the given `amount` of `token_address`. """
        # pylint: disable=too-many-arguments

        async_result = self.transfer_async(
            token_address,
            amount,
            target,
            identifier,
        )
        return async_result.wait(timeout=timeout)

    # expose a synchronous interface to the user
    token_swap = token_swap_and_wait
    transfer = transfer_and_wait  # expose a synchronous interface to the user

    def transfer_async(
            self,
            token_address,
            amount,
            target,
            identifier=None):
        # pylint: disable=too-many-arguments

        if not isinstance(amount, int):
            raise InvalidAmount('Amount not a number')

        if amount <= 0:
            raise InvalidAmount('Amount negative')

        if not isaddress(token_address) or token_address not in self.tokens:
            raise InvalidAddress('token address is not valid.')

        if not isaddress(target):
            raise InvalidAddress('target address is not valid.')

        graph = self.raiden.token_to_channelgraph[token_address]
        if not graph.has_path(self.raiden.address, target):
            raise NoPathError('No path to address found')

        log.debug(
            'initiating transfer',
            initiator=pex(self.raiden.address),
            target=pex(target),
            token=pex(token_address),
            amount=amount,
            identifier=identifier
        )

        async_result = self.raiden.mediated_transfer_async(
            token_address,
            amount,
            target,
            identifier,
        )
        return async_result

    def close(self, token_address, partner_address):
        """ Close a channel opened with `partner_address` for the given `token_address`. """

        if not isaddress(token_address):
            raise InvalidAddress('Expected binary address format for token in channel close')

        if not isaddress(partner_address):
            raise InvalidAddress('Expected binary address format for partner in channel close')

        if not isaddress(token_address) or token_address not in self.tokens:
            raise InvalidAddress('token address is not valid.')

        if not isaddress(partner_address):
            raise InvalidAddress('partner_address is not valid.')

        graph = self.raiden.token_to_channelgraph[token_address]
        channel = graph.partneraddress_to_channel[partner_address]

        balance_proof = channel.partner_state.balance_proof
        channel.external_state.close(balance_proof)

        return channel

    def settle(self, token_address, partner_address):
        """ Settle a closed channel with `partner_address` for the given `token_address`. """

        if not isaddress(token_address):
            raise InvalidAddress('Expected binary address format for token in channel settle')

        if not isaddress(partner_address):
            raise InvalidAddress('Expected binary address format for partner in channel settle')

        if not isaddress(token_address) or token_address not in self.tokens:
            raise InvalidAddress('token address is not valid.')

        if not isaddress(partner_address):
            raise InvalidAddress('partner_address is not valid.')

        graph = self.raiden.token_to_channelgraph[token_address]
        channel = graph.partneraddress_to_channel[partner_address]

        if channel.can_transfer:
            raise InvalidState('channel is still open.')

        netting_channel = channel.external_state.netting_channel

        current_block = self.raiden.chain.block_number()
        settle_timeout = netting_channel.detail()['settle_timeout']
        settle_expiration = channel.external_state.closed_block + settle_timeout

        if current_block <= settle_expiration:
            raise InvalidState('settlement period is not yet over.')

        netting_channel.settle()
        return channel

    def get_token_network_events(self, token_address, from_block, to_block):
        if not isaddress(token_address):
            raise InvalidAddress(
                'Expected binary address format for token in get_token_network_events'
            )

        try:
            graph = self.raiden.token_to_channelgraph[token_address]

            return get_all_channel_manager_events(
                self.raiden.chain,
                graph.channelmanager_address,
                events=ALL_EVENTS,
                from_block=from_block,
                to_block=to_block,
            )
        except KeyError:
            raise UnknownTokenAddress('The token address is not registered.')

    def get_network_events(self, from_block, to_block):
        registry_address = self.raiden.default_registry.address

        return get_all_registry_events(
            self.raiden.chain,
            registry_address,
            events=ALL_EVENTS,
            from_block=from_block,
            to_block=to_block,
        )

    def get_channel_events(self, channel_address, from_block, to_block=None):
        if not isaddress(channel_address):
            raise InvalidAddress(
                'Expected binary address format for channel in get_channel_events'
            )
        returned_events = get_all_netting_channel_events(
            self.raiden.chain,
            channel_address,
            events=ALL_EVENTS,
            from_block=from_block,
            to_block=to_block,
        )
        raiden_events = self.raiden.transaction_log.get_events_in_block_range(
            from_block=from_block,
            to_block=to_block
        )
        # Here choose which raiden internal events we want to expose to the end user
        for event in raiden_events:
            is_user_transfer_event = isinstance(event.event_object, (
                EventTransferSentSuccess,
                EventTransferSentFailed,
                EventTransferReceivedSuccess
            ))

            if is_user_transfer_event:
                new_event = {
                    'block_number': event.block_number,
                    '_event_type': type(event.event_object).__name__.encode(),
                }
                new_event.update(event.event_object.__dict__)
                returned_events.append(new_event)

        return returned_events
