# -*- coding: utf-8 -*-
from binascii import hexlify

import gevent
from ethereum import slogging
from ethereum.tools.tester import TransactionFailed

from raiden import waiting
from raiden.blockchain.events import (
    ALL_EVENTS,
    get_all_channel_manager_events,
    get_all_registry_events,
    get_all_netting_channel_events,
)
from raiden.transfer import views
from raiden.transfer.events import (
    EventTransferSentSuccess,
    EventTransferSentFailed,
    EventTransferReceivedSuccess,
)
from raiden.transfer.state_change import (
    ActionForTokenNetwork,
    ActionChannelClose,
)
from raiden.exceptions import (
    AlreadyRegisteredTokenAddress,
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

EVENTS_EXTERNALLY_VISIBLE = (
    EventTransferSentSuccess,
    EventTransferSentFailed,
    EventTransferReceivedSuccess,
)


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

        raise AlreadyRegisteredTokenAddress('Token already registered')

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
            raise UnknownTokenAddress('Unknown token address')

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


class RaidenAPI2:
    # pylint: disable=too-many-public-methods

    def __init__(self, raiden):
        self.raiden = raiden

    @property
    def address(self):
        return self.raiden.address

    # XXX: This interface will break once the channel identifiers are not addresses
    def get_channel(self, channel_address):
        if not isaddress(channel_address):
            raise InvalidAddress('Expected binary address format for channel in get_channel')

        channel_list = self.get_channel_list()
        for channel in channel_list:
            if channel.identifier == channel_address:
                return channel

        raise ChannelNotFound()

    def token_network_register(self, token_address):
        """Register the `token_address` in the blockchain.

        Raises:
            InvalidAddress: If the token_address is not a valid address.
            AlreadyRegisteredTokenAddress: If the token is already registered.
            TransactionThrew: If the register transaction failed, this may
                happen because the account has not enough balance to pay for the
                gas or this register call raced with another transaction and lost.
        """

        if not isaddress(token_address):
            raise InvalidAddress('token_address must be a valid address in binary')

        if token_address in self.get_tokens_list():
            raise AlreadyRegisteredTokenAddress('Token already registered')

        try:
            return self.raiden.default_registry.add_token(token_address)
        finally:
            # Assume the transaction failed because the token is already
            # registered with the smart contract and this node has not yet
            # polled for the event (otherwise the check above would have
            # failed).
            # To provide a consistent view to the user, force an event poll to
            # register the token network.
            self.raiden.poll_blockchain_events()

    def token_network_connect(
            self,
            token_address,
            funds,
            initial_channel_target=3,
            joinable_funds_target=.4):
        """Automatically maintain channels open for the given token network.

        Args:
            token_address (bin): the ERC20 token network to connect to.
            funds (int): the amount of funds that can be used by the ConnectionMananger.
            initial_channel_target (int): number of channels to open proactively.
            joinable_funds_target (float): fraction of the funds that will be used to join
                channels opened by other participants.
        """
        if not isaddress(token_address):
            raise InvalidAddress('token_address must be a valid address in binary')

        connection_manager = self.raiden.connection_manager_for_token(token_address)
        connection_manager.connect(
            funds,
            initial_channel_target=initial_channel_target,
            joinable_funds_target=joinable_funds_target
        )

    def token_network_leave(self, token_address, only_receiving=True):
        """Close all channels and wait for settlement."""
        if not isaddress(token_address):
            raise InvalidAddress('token_address must be a valid address in binary')

        if token_address not in self.get_tokens_list():
            raise UnknownTokenAddress('token_address unknown')

        connection_manager = self.raiden.connection_manager_for_token(token_address)
        return connection_manager.leave(only_receiving)

    def channel_open(
            self,
            token_address,
            partner_address,
            settle_timeout=None,
            reveal_timeout=None,
            poll_timeout=DEFAULT_POLL_TIMEOUT):
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
        netcontract_address = channel_manager.new_netting_channel(
            partner_address,
            settle_timeout,
        )

        msg = 'After {} seconds the channel was not properly created.'.format(
            poll_timeout
        )

        registry_address = self.raiden.default_registry.address
        with gevent.Timeout(poll_timeout, EthNodeCommunicationError(msg)):
            waiting.wait_for_newchannel(
                self.raiden,
                registry_address,
                token_address,
                partner_address,
                self.raiden.alarm.wait_time,
            )

        return netcontract_address

    def channel_deposit(
            self,
            token_address,
            partner_address,
            amount,
            poll_timeout=DEFAULT_POLL_TIMEOUT):
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
        node_state = views.state_from_raiden(self.raiden)
        registry_address = self.raiden.default_registry.address

        token_networks = views.get_token_network_addresses_for(
            node_state,
            registry_address,
        )
        channel_state = views.get_channelstate_for(
            node_state,
            registry_address,
            token_address,
            partner_address,
        )

        if not isaddress(token_address):
            raise InvalidAddress('Expected binary address format for token in channel deposit')

        if not isaddress(partner_address):
            raise InvalidAddress('Expected binary address format for partner in channel deposit')

        if token_address not in token_networks:
            raise UnknownTokenAddress('Unknown token address')

        if channel_state is None:
            raise InvalidAddress('No channel with partner_address for the given token')

        token = self.raiden.chain.token(token_address)
        balance = token.balance_of(hexlify(self.raiden.address))

        # If this check succeeds it does not imply the the `deposit` will
        # succeed, since the `deposit` transaction may race with another
        # transaction.
        if not balance >= amount:
            msg = 'Not enough balance to deposit. {} Available={} Tried={}'.format(
                pex(token_address),
                balance,
                amount,
            )
            raise InsufficientFunds(msg)

        netcontract_address = channel_state.identifier
        token.approve(netcontract_address, amount)

        channel_proxy = self.raiden.chain.netting_channel(netcontract_address)
        channel_proxy.deposit(amount)

        old_balance = channel_state.our_state.contract_balance
        target_balance = old_balance + amount

        msg = 'After {} seconds the deposit was not properly processed.'.format(
            poll_timeout
        )

        # Wait until the `ChannelNewBalance` event is processed.
        with gevent.Timeout(poll_timeout, EthNodeCommunicationError(msg)):
            waiting.wait_for_newbalance(
                self.raiden,
                registry_address,
                token_address,
                partner_address,
                target_balance,
                self.raiden.alarm.wait_time,
            )

    def channel_close(self, token_address, partner_address, poll_timeout=DEFAULT_POLL_TIMEOUT):
        """Close a channel opened with `partner_address` for the given
        `token_address`.

        Race condition, this can fail if channel was closed externally.
        """
        self.channel_batch_close(
            token_address,
            [partner_address],
            poll_timeout,
        )

    def channel_batch_close(
            self,
            token_address,
            partner_addresses,
            poll_timeout=DEFAULT_POLL_TIMEOUT):
        """Close a channel opened with `partner_address` for the given
        `token_address`.

        Race condition, this can fail if channel was closed externally.
        """

        if not isaddress(token_address):
            raise InvalidAddress('Expected binary address format for token in channel close')

        if not all(map(isaddress, partner_addresses)):
            raise InvalidAddress('Expected binary address format for partner in channel close')

        valid_tokens = views.get_token_network_addresses_for(
            views.state_from_raiden(self.raiden),
            self.raiden.default_registry.address,
        )
        if token_address not in valid_tokens:
            raise UnknownTokenAddress('Token address is not known.')

        registry_address = self.raiden.default_registry.address
        node_state = views.state_from_raiden(self.raiden)
        channels_to_close = views.filter_channels_by_partneraddress(
            node_state,
            registry_address,
            token_address,
            partner_addresses,
        )

        for channel_state in channels_to_close:
            channel_close = ActionChannelClose(channel_state.identifier)
            state_change = ActionForTokenNetwork(
                registry_address,
                token_address,
                channel_close,
            )
            self.raiden.handle_state_change(state_change)

        msg = 'After {} seconds the deposit was not properly processed.'.format(
            poll_timeout
        )
        channel_ids = [channel_state.identifier for channel_state in channels_to_close]

        with gevent.Timeout(poll_timeout, EthNodeCommunicationError(msg)):
            waiting.wait_for_close(
                self.raiden,
                registry_address,
                token_address,
                channel_ids,
                self.raiden.alarm.wait_time,
            )

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

        registry_address = self.raiden.default_registry.address

        result = list()
        if token_address and partner_address:
            channel_state = views.get_channelstate_for(
                views.state_from_raiden(self.raiden),
                registry_address,
                token_address,
                partner_address,
            )

            if channel_state:
                result = [channel_state]
            else:
                result = []

        elif token_address:
            result = views.list_channelstate_for_tokennetwork(
                views.state_from_raiden(self.raiden),
                registry_address,
                token_address,
            )

        elif partner_address:
            result = views.list_channelstate_for_tokennetwork(
                views.state_from_raiden(self.raiden),
                registry_address,
                partner_address,
            )

        else:
            result = views.list_all_channelstate(
                views.state_from_raiden(self.raiden),
            )

        return result

    def get_node_network_state(self, node_address):
        """ Returns the currently network status of `node_address`. """
        return views.get_node_network_status(
            views.state_from_raiden(self.raiden),
            node_address,
        )

    def start_health_check_for(self, node_address):
        """ Returns the currently network status of `node_address`. """
        self.raiden.start_health_check_for(node_address)

    def get_tokens_list(self):
        """Returns a list of tokens the node knows about"""
        tokens_list = views.get_token_network_addresses_for(
            views.state_from_raiden(self.raiden),
            self.raiden.default_registry.address,
        )
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

    def transfer_async(
            self,
            token_address,
            amount,
            target,
            identifier=None):

        if not isinstance(amount, int):
            raise InvalidAmount('Amount not a number')

        if amount <= 0:
            raise InvalidAmount('Amount negative')

        if not isaddress(token_address):
            raise InvalidAddress('token address is not valid.')

        if not isaddress(target):
            raise InvalidAddress('target address is not valid.')

        valid_tokens = views.get_token_network_addresses_for(
            views.state_from_raiden(self.raiden),
            self.raiden.default_registry.address,
        )
        if token_address not in valid_tokens:
            raise UnknownTokenAddress('Token address is not known.')

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

    def get_network_events(self, from_block, to_block):
        registry_address = self.raiden.default_registry.address

        return get_all_registry_events(
            self.raiden.chain,
            registry_address,
            events=ALL_EVENTS,
            from_block=from_block,
            to_block=to_block,
        )

    def get_channel_events(self, channel_address, from_block, to_block='latest'):
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
        raiden_events = self.raiden.wal.storage.get_events_by_block(
            from_block=from_block,
            to_block=to_block,
        )
        # Here choose which raiden internal events we want to expose to the end user
        for block_number, event in raiden_events:
            if isinstance(event, EVENTS_EXTERNALLY_VISIBLE):
                new_event = {
                    'block_number': block_number,
                    '_event_type': type(event).__name__.encode(),
                }
                new_event.update(event.__dict__)
                returned_events.append(new_event)

        return returned_events

    transfer = transfer_and_wait
