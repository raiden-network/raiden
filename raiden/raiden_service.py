# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines
import logging
import random
import itertools
from collections import defaultdict

import gevent
from gevent.event import AsyncResult
from ethereum import slogging
from ethereum.utils import encode_hex
from secp256k1 import PrivateKey
from pyethapp.jsonrpc import address_decoder

from raiden.blockchain.events import (
    ALL_EVENTS,
    get_relevant_proxies,
    get_all_channel_manager_events,
    get_all_registry_events,
    get_all_netting_channel_events,
    PyethappBlockchainEvents,
)
from raiden.tasks import (
    AlarmTask,
    EndMediatedTransferTask,
    HealthcheckTask,
)
from raiden.transfer.architecture import (
    StateManager,
)
from raiden.transfer.state import (
    RoutesState,
)
from raiden.transfer.mediated_transfer import (
    initiator,
    mediator,
)
from raiden.transfer.mediated_transfer.state import (
    lockedtransfer_from_message,
    InitiatorState,
    MediatorState,
    LockedTransferState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ContractReceiveBalance,
    ContractReceiveClosed,
    ContractReceiveNewChannel,
    ContractReceiveSettled,
    ContractReceiveTokenAdded,
    ContractReceiveWithdraw,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
)
from raiden.transfer.mediated_transfer.events import (
    EventTransferCompleted,
    EventTransferFailed,
    SendBalanceProof,
    SendMediatedTransfer,
    SendRefundTransfer,
    SendRevealSecret,
    SendSecretRequest,
)
from raiden.channel import ChannelEndState, ChannelExternalState
from raiden.exceptions import (
    UnknownAddress,
    TransferWhenClosed,
    UnknownTokenAddress,
    NoPathError,
    InvalidAddress,
    InvalidAmount,
    InvalidState,
    InsufficientFunds,
)
from raiden.network.channelgraph import (
    channel_to_routestate,
    route_to_routestate,
    ChannelGraph,
    ChannelDetail,
)
from raiden.encoding import messages
from raiden.messages import (
    SignedMessage,
    RevealSecret,
    Secret,
)
from raiden.network.protocol import RaidenProtocol
from raiden.utils import (
    isaddress,
    pex,
    privatekey_to_address,
    safe_address_decode,
    sha3,
    GLOBAL_CTX,
)

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


def create_default_identifier(node_address, token_address, target):
    """
    The default message identifier value is the first 8 bytes of the sha3 of:
        - Our Address
        - Our target address
        - The token address
        - A random 8 byte number for uniqueness
    """
    hash_ = sha3("{}{}{}{}".format(
        node_address,
        target,
        token_address,
        random.randint(0, 18446744073709551614L)
    ))
    return int(hash_[0:8].encode('hex'), 16)


class RandomSecretGenerator(object):  # pylint: disable=too-few-public-methods
    def __next__(self):  # pylint: disable=no-self-use
        secret = sha3(hex(random.getrandbits(256)))
        return secret

    next = __next__


class RaidenService(object):
    """ A Raiden node. """
    # pylint: disable=too-many-instance-attributes,too-many-public-methods

    def __init__(self, chain, private_key_bin, transport, discovery, config):
        # pylint: disable=too-many-arguments

        if not isinstance(private_key_bin, bytes) or len(private_key_bin) != 32:
            raise ValueError('invalid private_key')

        private_key = PrivateKey(
            private_key_bin,
            ctx=GLOBAL_CTX,
            raw=True,
        )
        pubkey = private_key.pubkey.serialize(compressed=False)

        self.channelgraphs = dict()
        self.manager_token = dict()

        self.hashlock_token_task = defaultdict(dict)
        self.identifier_statemanager = defaultdict(list)
        self.identifier_result = defaultdict(list)

        # This is a map from a hashlock to a list of channels, the same
        # hashlock can be used in more than one token (for exchanges), a
        # channel should be removed from this list only when the lock is
        # released/withdrawed but not when the secret is registered.
        self.hashlock_channel = defaultdict(lambda: defaultdict(list))

        self.chain = chain
        self.config = config
        self.privkey = private_key_bin
        self.pubkey = pubkey
        self.private_key = private_key
        self.address = privatekey_to_address(private_key_bin)
        self.protocol = RaidenProtocol(transport, discovery, self)
        transport.protocol = self.protocol

        message_handler = RaidenMessageHandler(self)
        state_machine_event_handler = StateMachineEventHandler(self)
        pyethapp_blockchain_events = PyethappBlockchainEvents()

        alarm = AlarmTask(chain)
        # ignore the blocknumber
        alarm.register_callback(self.poll_blockchain_events)
        alarm.start()

        self._blocknumber = alarm.last_block_number
        alarm.register_callback(self.set_block_number)

        if config['max_unresponsive_time'] > 0:
            self.healthcheck = HealthcheckTask(
                self,
                config['send_ping_time'],
                config['max_unresponsive_time']
            )
            self.healthcheck.start()
        else:
            self.healthcheck = None

        self.api = RaidenAPI(self)
        self.alarm = alarm
        self.message_handler = message_handler
        self.state_machine_event_handler = state_machine_event_handler
        self.pyethapp_blockchain_events = pyethapp_blockchain_events

        self.on_message = message_handler.on_message

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.address))

    def set_block_number(self, blocknumber):
        self._blocknumber = blocknumber

    def get_block_number(self):
        return self._blocknumber

    def poll_blockchain_events(self, block_number):  # pylint: disable=unused-argument
        on_statechange = self.state_machine_event_handler.on_blockchain_statechange

        for state_change in self.pyethapp_blockchain_events.poll_state_change():
            on_statechange(state_change)

    def find_channel_by_address(self, netting_channel_address_bin):
        for graph in self.channelgraphs.itervalues():
            channel = graph.address_channel.get(netting_channel_address_bin)

            if channel is not None:
                return channel

        raise ValueError('unknown channel {}'.format(encode_hex(netting_channel_address_bin)))

    def sign(self, message):
        """ Sign message inplace. """
        if not isinstance(message, SignedMessage):
            raise ValueError('{} is not signable.'.format(repr(message)))

        message.sign(self.private_key, self.address)

    def send(self, *args):
        raise NotImplementedError('use send_and_wait or send_async')

    def send_async(self, recipient, message):
        """ Send `message` to `recipient` using the raiden protocol.

        The protocol will take care of resending the message on a given
        interval until an Acknowledgment is received or a given number of
        tries.
        """

        if not isaddress(recipient):
            raise ValueError('recipient is not a valid address.')

        if recipient == self.address:
            raise ValueError('programming error, sending message to itself')

        return self.protocol.send_async(recipient, message)

    def send_and_wait(self, recipient, message, timeout):
        """ Send `message` to `recipient` and wait for the response or `timeout`.

        Args:
            recipient (address): The address of the node that will receive the
                message.
            message: The transfer message.
            timeout (float): How long should we wait for a response from `recipient`.

        Returns:
            None: If the wait timed out
            object: The result from the event
        """
        if not isaddress(recipient):
            raise ValueError('recipient is not a valid address.')

        self.protocol.send_and_wait(recipient, message, timeout)

    # api design regarding locks:
    # - `register_secret` method was added because secret registration can be a
    #   cross token operation
    # - unlocking a lock is not a cross token operation, for this reason it's
    #   only available in the token manager

    def register_secret(self, secret):
        """ Register the secret with any channel that has a hashlock on it.

        This must search through all channels registered for a given hashlock
        and ignoring the tokens. Useful for refund transfer, split transfer,
        and exchanges.
        """
        hashlock = sha3(secret)
        revealsecret_message = RevealSecret(secret)
        self.sign(revealsecret_message)

        for hash_channel in self.hashlock_channel.itervalues():
            for channel in hash_channel[hashlock]:
                try:
                    channel.register_secret(secret)

                    # This will potentially be executed multiple times and could suffer
                    # from amplification, the protocol will ignore messages that were
                    # already registered and send it only until a first Ack is
                    # received.
                    self.send_async(
                        channel.partner_state.address,
                        revealsecret_message,
                    )
                except:  # pylint: disable=bare-except
                    # Only channels that care about the given secret can be
                    # registered and channels that have claimed the lock must
                    # be removed, so an exception should not happen at this
                    # point, nevertheless handle it because we dont want a
                    # error in a channel to mess the state from others.
                    log.error('programming error')

    def register_task_for_hashlock(self, task, token, hashlock):
        """ Register the task to receive messages based on hashlock.

        Registration is required otherwise the task won't receive any messages
        from the protocol, un-registering is done by the `on_hashlock_result`
        function.

        Note:
            Messages are dispatched solely on the hashlock value (being part of
            the message, eg. SecretRequest, or calculated from the message
            content, eg.  RevealSecret), this means the sender needs to be
            checked for the received messages.
        """
        self.hashlock_token_task[hashlock][token] = task

    def register_channel_for_hashlock(self, token_address, channel, hashlock):
        channels_registered = self.hashlock_channel[token_address][hashlock]

        if channel not in channels_registered:
            channels_registered.append(channel)

    def handle_secret(  # pylint: disable=too-many-arguments
            self,
            identifier,
            token_address,
            secret,
            partner_secret_message,
            hashlock):
        """ Unlock/Witdraws locks, register the secret, and send Secret
        messages as necessary.

        This function will:
            - Unlock the locks created by this node and send a Secret message to
            the corresponding partner so that she can withdraw the token.
            - Withdraw the lock from sender.
            - Register the secret for the locks received and reveal the secret
            to the senders

        Note:
            The channel needs to be registered with
            `raiden.register_channel_for_hashlock`.
        """
        # handling the secret needs to:
        # - unlock the token for all `forward_channel` (the current one
        #   and the ones that failed with a refund)
        # - send a message to each of the forward nodes allowing them
        #   to withdraw the token
        # - register the secret for the `originating_channel` so that a
        #   proof can be made, if necessary
        # - reveal the secret to the `sender` node (otherwise we
        #   cannot withdraw the token)
        channels_list = self.hashlock_channel[token_address][hashlock]
        channels_to_remove = list()

        # Dont use the partner_secret_message.token since it might not match with the
        # current token manager
        our_secret_message = Secret(
            identifier,
            secret,
            token_address,
        )
        self.sign(our_secret_message)

        revealsecret_message = RevealSecret(secret)
        self.sign(revealsecret_message)

        for channel in channels_list:
            # unlock a sent lock
            if channel.partner_state.balance_proof.is_unclaimed(hashlock):
                channel.release_lock(secret)
                self.send_async(
                    channel.partner_state.address,
                    our_secret_message,
                )
                channels_to_remove.append(channel)

            # withdraw a pending lock
            if channel.our_state.balance_proof.is_unclaimed(hashlock):
                if partner_secret_message:
                    valid_sender = partner_secret_message.sender == channel.partner_state.address
                    valid_token = partner_secret_message.token == channel.token_address

                    if valid_sender and valid_token:
                        channel.withdraw_lock(secret)
                        channels_to_remove.append(channel)
                    else:
                        channel.register_secret(secret)
                        self.send_async(
                            channel.partner_state.address,
                            revealsecret_message,
                        )
                else:
                    channel.register_secret(secret)
                    self.send_async(
                        channel.partner_state.address,
                        revealsecret_message,
                    )

        for channel in channels_to_remove:
            channels_list.remove(channel)

        if len(channels_list) == 0:
            del self.hashlock_channel[token_address][hashlock]

    def get_channel_detail(self, token_address, netting_channel):
        channel_details = netting_channel.detail(self.address)
        our_state = ChannelEndState(
            channel_details['our_address'],
            channel_details['our_balance'],
            netting_channel.opened,
        )
        partner_state = ChannelEndState(
            channel_details['partner_address'],
            channel_details['partner_balance'],
            netting_channel.opened,
        )

        def register_channel_for_hashlock(channel, hashlock):
            self.register_channel_for_hashlock(
                token_address,
                channel,
                hashlock,
            )

        channel_address = netting_channel.address
        reveal_timeout = self.config['reveal_timeout']
        settle_timeout = channel_details['settle_timeout']

        external_state = ChannelExternalState(
            self.alarm.register_callback,
            register_channel_for_hashlock,
            self.get_block_number,
            netting_channel,
        )

        channel_detail = ChannelDetail(
            channel_address,
            our_state,
            partner_state,
            external_state,
            reveal_timeout,
            settle_timeout,
        )

        return channel_detail

    def on_hashlock_result(self, token, hashlock, success):  # pylint: disable=unused-argument
        """ Clear the task when it's finished. """
        del self.hashlock_token_task[hashlock][token]

        if len(self.hashlock_token_task[hashlock]) == 0:
            del self.hashlock_token_task[hashlock]

    def message_for_task(self, message, hashlock):
        """ Sends the message to the corresponding task.

        The corresponding task is found by matching the hashlock.

        Return:
            Nothing if a corresponding task is found,raise Exception otherwise
        """

        if self.hashlock_token_task[hashlock]:
            for task in self.hashlock_token_task[hashlock].itervalues():
                task.on_response(message)

        else:
            raise UnknownAddress('Received unexpected {}, sender: {}'.format(
                message.__class__.__name__,
                pex(message.sender),
            ))

    def register_registry(self, registry_address):
        proxies = get_relevant_proxies(
            self.chain,
            self.address,
            registry_address,
        )

        # Install the filters first to avoid missing changes, as a consequence
        # some events might be applied twice.
        self.pyethapp_blockchain_events.add_proxies_listeners(proxies)

        for manager in proxies.channel_managers:
            token_address = manager.token_address()
            manager_address = manager.address

            channels_detail = list()
            netting_channels = proxies.channelmanager_nettingchannels[manager_address]
            for channel in netting_channels:
                detail = self.get_channel_detail(token_address, channel)
                channels_detail.append(detail)

            edge_list = manager.channels_addresses()
            graph = ChannelGraph(
                self.address,
                manager_address,
                token_address,
                edge_list,
                channels_detail
            )

            self.manager_token[manager_address] = token_address
            self.channelgraphs[token_address] = graph

    def register_channel_manager(self, manager_address):
        manager = self.chain.manager(manager_address)
        netting_channels = [
            self.chain.netting_channel(channel_address)
            for channel_address in manager.channels_by_participant(self.address)
        ]

        # Install the filters first to avoid missing changes, as a consequence
        # some events might be applied twice.
        self.pyethapp_blockchain_events.add_channel_manager_listener(manager)
        for channel in netting_channels:
            self.pyethapp_blockchain_events.add_netting_channel_listener(channel)

        token_address = manager.token_address()
        edge_list = manager.channels_addresses()
        channels_detail = [
            self.get_channel_detail(token_address, channel)
            for channel in netting_channels
        ]

        graph = ChannelGraph(
            self.address,
            manager_address,
            token_address,
            edge_list,
            channels_detail,
        )

        self.manager_token[manager_address] = token_address
        self.channelgraphs[token_address] = graph

    def register_netting_channel(self, token_address, channel_address):
        netting_channel = self.chain.netting_channel(channel_address)
        self.pyethapp_blockchain_events.add_netting_channel_listener(netting_channel)

        detail = self.get_channel_detail(token_address, netting_channel)
        graph = self.channelgraphs[token_address]
        graph.add_channel(detail)

    def stop(self):
        wait_for = [self.alarm]

        for token_task in self.hashlock_token_task.itervalues():
            for task in token_task.itervalues():
                task.kill()

            wait_for.extend(token_task.itervalues())

        self.alarm.stop_async()
        if self.healthcheck is not None:
            self.healthcheck.stop_async()
            wait_for.append(self.healthcheck)
        self.protocol.stop_async()

        wait_for.extend(self.protocol.address_greenlet.itervalues())

        self.pyethapp_blockchain_events.uninstall_all_event_listeners()
        gevent.wait(wait_for)

    def transfer_async(self, token_address, amount, target, identifier=None):
        """ Transfer `amount` between this node and `target`.

        This method will start an asyncronous transfer, the transfer might fail
        or succeed depending on a couple of factors:
            - Existence of a path that can be used, through the usage of direct
            or intermediary channels.
            - Network speed, making the transfer suficiently fast so it doesn't
            timeout.
        """
        graph = self.channelgraphs[token_address]

        if identifier is None:
            identifier = create_default_identifier(self.address, token_address, target)

        direct_channel = graph.partneraddress_channel.get(target)
        if direct_channel:
            async_result = self._direct_or_mediated_transfer(
                token_address,
                amount,
                identifier,
                direct_channel,
            )
            return async_result

        else:
            async_result = self._mediated_transfer(
                token_address,
                amount,
                identifier,
                target,
            )

            return async_result

    def _direct_or_mediated_transfer(self, token_address, amount, identifier, direct_channel):
        """ Check the direct channel and if possible use it, otherwise start a
        mediated transfer.
        """

        if not direct_channel.isopen:
            log.info(
                'DIRECT CHANNEL %s > %s is closed',
                pex(direct_channel.our_state.address),
                pex(direct_channel.partner_state.address),
            )

            async_result = self._mediated_transfer(
                token_address,
                amount,
                identifier,
                direct_channel.partner_state.address,
            )
            return async_result

        elif amount > direct_channel.distributable:
            log.info(
                'DIRECT CHANNEL %s > %s doesnt have enough funds [%s]',
                pex(direct_channel.our_state.address),
                pex(direct_channel.partner_state.address),
                amount,
            )

            async_result = self._mediated_transfer(
                token_address,
                amount,
                identifier,
                direct_channel.partner_state.address,
            )
            return async_result

        else:
            direct_transfer = direct_channel.create_directtransfer(amount, identifier)
            self.sign(direct_transfer)
            direct_channel.register_transfer(direct_transfer)

            async_result = self.protocol.send_async(
                direct_channel.partner_state.address,
                direct_transfer,
            )
            return async_result

    def _mediated_transfer(self, token_address, amount, identifier, target):
        return self.start_mediated_transfer(token_address, amount, identifier, target)

    def start_mediated_transfer(self, token_address, amount, identifier, target):
        # pylint: disable=too-many-locals
        graph = self.channelgraphs[token_address]
        routes = graph.get_best_routes(
            self.address,
            target,
            amount,
            lock_timeout=None,
        )

        available_routes = [
            route
            for route in map(route_to_routestate, routes)
            if route.state == 'opened'
        ]

        identifier = create_default_identifier(self.address, token_address, target)
        route_state = RoutesState(available_routes)
        our_address = self.address
        block_number = self.get_block_number()

        transfer_state = LockedTransferState(
            identifier=identifier,
            amount=amount,
            token=token_address,
            initiator=self.address,
            target=target,
            expiration=None,
            hashlock=None,
            secret=None,
        )

        # Raiden might fail after a state change that uses the random generator
        # and it's events are processed but before the snapshot is taken. If
        # that happens on the next initialization when raiden is recovering and
        # applying the pending state changes a new secret will be generated and
        # the resulting events won't match, this breaks the architecture model,
        # since it's assumed the re-execution of a state change will always
        # produce the same events.
        #
        # TODO: Removed the secret generator from the InitiatorState and add
        # the secret into all state changes that required one, this way the
        # secret will be serialized with the state change and the recovery will
        # use the same /random/ secret.
        random_generator = RandomSecretGenerator()

        init_initiator = ActionInitInitiator(
            our_address=our_address,
            transfer=transfer_state,
            routes=route_state,
            random_generator=random_generator,
            block_number=block_number,
        )

        state_manager = StateManager(initiator.state_transition, None)
        all_events = state_manager.dispatch(init_initiator)

        for event in all_events:
            self.state_machine_event_handler.on_event(event)

        async_result = AsyncResult()

        # TODO: implement the network timeout raiden.config['msg_timeout'] and
        # cancel the current transfer it hapens
        self.identifier_statemanager[identifier].append(state_manager)
        self.identifier_result[identifier].append(async_result)

        return async_result

    def mediate_mediated_transfer(self, message):
        # pylint: disable=too-many-locals
        identifier = message.identifier
        amount = message.lock.amount
        target = message.target
        token = message.token
        graph = self.channelgraphs[token]
        routes = graph.get_best_routes(
            self.address,
            target,
            amount,
            lock_timeout=None,
        )

        available_routes = [
            route
            for route in map(route_to_routestate, routes)
            if route.state == 'opened'
        ]

        from_channel = graph.partneraddress_channel[message.sender]
        from_route = channel_to_routestate(from_channel, message.sender)

        our_address = self.address
        from_transfer = lockedtransfer_from_message(message)
        route_state = RoutesState(available_routes)
        block_number = self.get_block_number()

        init_mediator = ActionInitMediator(
            our_address,
            from_transfer,
            route_state,
            from_route,
            block_number,
        )

        state_manager = StateManager(mediator.state_transition, None)
        all_events = state_manager.dispatch(init_mediator)

        for event in all_events:
            self.state_machine_event_handler.on_event(event)

        self.identifier_statemanager[identifier].append(state_manager)


class RaidenAPI(object):
    """ CLI interface. """

    def __init__(self, raiden):
        self.raiden = raiden

    @property
    def address(self):
        return self.raiden.address

    @property
    def tokens(self):
        """ Return a list of the tokens registered with the default registry. """
        return self.raiden.chain.default_registry.token_addresses()

    def get_balance(self, token_address, partner_address):
        raise NotImplementedError()

    def get_completed_transfers(self, token_address=None, partner_address=None):
        raise NotImplementedError()

    def get_channel(self, channel_address):
        channel_address_bin = address_decoder(channel_address)
        channel_list = self.get_channel_list()
        for channel in channel_list:
            if channel.channel_address == channel_address_bin:
                return channel

        raise ValueError("Channel not found")

    def create_default_identifier(self, target, token_address):
        """
        The default message identifier value is the first 8 bytes of the sha3 of:
            - Our Address
            - Our target address
            - The token address
            - A random 8 byte number for uniqueness
        """
        return self.raiden.create_default_identifier(target, token_address)

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

        if settle_timeout < self.raiden.config['settle_timeout']:
            raise ValueError('Configured minimum `settle_timeout` is {} blocks.'.format(
                self.raiden.config['settle_timeout']
            ))

        token_address_bin = token_address.decode('hex')

        channel_manager = self.raiden.chain.manager_by_token(token_address_bin)
        assert token_address_bin in self.raiden.channelgraphs

        netcontract_address = channel_manager.new_netting_channel(
            self.raiden.address,
            partner_address.decode('hex'),
            settle_timeout,
        )
        netting_channel = self.raiden.chain.netting_channel(netcontract_address)
        self.raiden.register_channel(netting_channel, reveal_timeout)

        graph = self.raiden.channelgraphs[token_address_bin]
        channel = graph.partneraddress_channel[partner_address.decode('hex')]
        return channel

    def deposit(self, token_address, partner_address, amount):
        """ Deposit `amount` in the channel with the peer at `partner_address` and the
        given `token_address` in order to be able to do transfers.
        """
        graph = self.raiden.channelgraphs[token_address.decode('hex')]
        channel = graph.partneraddress_channel[partner_address.decode('hex')]
        netcontract_address = channel.external_state.netting_channel.address
        assert len(netcontract_address)

        # Obtain a reference to the token and approve the amount for funding
        token = self.raiden.chain.token(token_address.decode('hex'))
        balance = token.balance_of(self.raiden.address.encode('hex'))

        if not balance >= amount:
            msg = "Not enough balance for token'{}' [{}]: have={}, need={}".format(
                token.proxy.name(), token_address, balance, amount
            )
            raise InsufficientFunds(msg)

        token.approve(netcontract_address, amount)

        # Obtain the netting channel and fund it by depositing the amount
        netting_channel = self.raiden.chain.netting_channel(netcontract_address)
        netting_channel.deposit(self.raiden.address, amount)

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
            KeyError:
                - An error occurred when the given partner address isn't associated
                  with the given token address.
                - An error occurred when the token address is unknown to the node.
        """
        if token_address and partner_address:
            graph = self.raiden.channelgraphs[token_address]

            # Let it raaise the KeyError
            channel = graph.partneraddress_channel[partner_address]

            return [channel]

        elif token_address:
            graph = self.raiden.channelgraphs[token_address]
            token_channels = graph.address_channel.values()
            return token_channels

        elif partner_address:
            partner_channels = [
                graph.partneraddress_channel[partner_address]
                for graph in self.raiden.channelgraphs.itervalues()
                if partner_address in graph.partneraddress_channel
            ]

            return partner_channels

        else:
            all_channels = list()
            for graph in self.raiden.channelgraphs.itervalues():
                all_channels.extend(graph.address_channel.itervalues())

            return all_channels

    def get_tokens_list(self):
        """Returns a list of tokens the node knows about"""
        tokens_list = list(self.raiden.channelgraphs.iterkeys())
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

    transfer = transfer_and_wait  # expose a synchronous interface to the user

    def transfer_async(
            self,
            token_address,
            amount,
            target,
            identifier=None):
        # pylint: disable=too-many-arguments

        if not isinstance(amount, (int, long)):
            raise InvalidAmount('Amount not a number')

        if amount <= 0:
            raise InvalidAmount('Amount negative')

        token_address_bin = safe_address_decode(token_address)
        target_bin = safe_address_decode(target)

        if not isaddress(token_address_bin) or token_address_bin not in self.tokens:
            raise InvalidAddress('token address is not valid.')

        if not isaddress(target_bin):
            raise InvalidAddress('target address is not valid.')

        graph = self.raiden.channelgraphs[token_address_bin]
        if not graph.has_path(self.raiden.address, target_bin):
            raise NoPathError('No path to address found')

        async_result = self.raiden.transfer_async(
            token_address_bin,
            amount,
            target_bin,
            identifier=identifier,
        )
        return async_result

    def close(self, token_address, partner_address):
        """ Close a channel opened with `partner_address` for the given `token_address`. """
        token_address_bin = safe_address_decode(token_address)
        partner_address_bin = safe_address_decode(partner_address)

        if not isaddress(token_address_bin) or token_address_bin not in self.tokens:
            raise InvalidAddress('token address is not valid.')

        if not isaddress(partner_address_bin):
            raise InvalidAddress('partner_address is not valid.')

        graph = self.raiden.channelgraphs[token_address_bin]
        channel = graph.partneraddress_channel[partner_address]

        first_transfer = None
        if channel.received_transfers:
            first_transfer = channel.received_transfers[-1]

        netting_channel = channel.external_state.netting_channel
        netting_channel.close(
            self.raiden.address,
            first_transfer,
        )

        return channel

    def settle(self, token_address, partner_address):
        """ Settle a closed channel with `partner_address` for the given `token_address`. """
        token_address_bin = safe_address_decode(token_address)
        partner_address_bin = safe_address_decode(partner_address)

        if not isaddress(token_address_bin) or token_address_bin not in self.tokens:
            raise InvalidAddress('token address is not valid.')

        if not isaddress(partner_address_bin):
            raise InvalidAddress('partner_address is not valid.')

        graph = self.raiden.channelgraphs[token_address_bin]
        channel = graph.partneraddress_channel[partner_address]

        if channel.isopen:
            raise InvalidState('channel is still open.')

        netting_channel = channel.external_state.netting_channel

        current_block = self.raiden.chain.block_number()
        settle_timeout = netting_channel.detail(self.raiden.address)['settle_timeout']
        settle_expiration = channel.external_state.closed_block + settle_timeout

        if current_block <= settle_expiration:
            raise InvalidState('settlement period is not yet over.')

        netting_channel.settle()
        return channel

    def get_token_network_events(self, token_address, from_block, to_block):
        token_address = address_decoder(token_address)
        graph = self.raiden.channelgraphs[token_address]
        graph.channelmanager_address

        return get_all_channel_manager_events(
            self.raiden.chain,
            graph.channelmanager_address,
            events=ALL_EVENTS,
            from_block=from_block,
            to_block=to_block,
        )

    def get_network_events(self, from_block, to_block):
        registry_address = self.raiden.chain.default_registry.address

        return get_all_registry_events(
            self.raiden.chain,
            registry_address,
            events=ALL_EVENTS,
            from_block=from_block,
            to_block=to_block,
        )

    def get_channel_events(self, channel_address, from_block, to_block):
        return get_all_netting_channel_events(
            self.raiden.chain,
            channel_address,
            events=ALL_EVENTS,
            from_block=from_block,
            to_block=to_block,
        )


class RaidenMessageHandler(object):
    """ Class responsible to handle the protocol messages.

    Note:
        This class is not intended to be used standalone, use RaidenService
        instead.
    """
    def __init__(self, raiden):
        self.raiden = raiden

    def on_message(self, message, msghash):  # noqa pylint: disable=unused-argument
        """ Handles `message` and sends an ACK on success. """
        if log.isEnabledFor(logging.INFO):
            log.info('message received', message=message)

        cmdid = message.cmdid

        # using explicity dispatch to make the code grepable
        if cmdid == messages.ACK:
            pass

        elif cmdid == messages.PING:
            pass

        elif cmdid == messages.SECRETREQUEST:
            self.message_secretrequest(message)

        elif cmdid == messages.REVEALSECRET:
            self.message_revealsecret(message)

        elif cmdid == messages.SECRET:
            self.message_secret(message)

        elif cmdid == messages.DIRECTTRANSFER:
            self.message_directtransfer(message)

        elif cmdid == messages.MEDIATEDTRANSFER:
            self.message_mediatedtransfer(message)

        elif cmdid == messages.REFUNDTRANSFER:
            self.message_refundtransfer(message)

        else:
            raise Exception("Unhandled message cmdid '{}'.".format(cmdid))

    def message_revealsecret(self, message):
        hashlock = message.hashlock
        secret = message.secret
        sender = message.sender

        try:
            self.raiden.message_for_task(message, hashlock)
        except UnknownAddress:
            # No gevent task registered for the given hashlock, trying state task

            # A payee node knows the secret, release the lock and update the
            # balance locally, next transfer message will have an updated
            # transferred_amount and merkle tree root
            for graph in self.raiden.channelgraphs.itervalues():
                channel = graph.partneraddress_channel.get(sender)

                unclaimed = (
                    channel is not None and
                    channel.partner_state.balance_proof.is_unclaimed(hashlock)
                )

                if unclaimed:
                    channel.release_lock(secret)

            state_change = ReceiveSecretReveal(secret, sender)
            self.raiden.state_machine_event_handler.dispatch_to_all_tasks(state_change)

    def message_secretrequest(self, message):
        try:
            self.raiden.message_for_task(message, message.hashlock)
        except UnknownAddress:
            # No gevent task registered for the given hashlock, trying state task

            if message.identifier in self.raiden.identifier_statemanager:
                state_change = ReceiveSecretRequest(
                    message.identifier,
                    message.amount,
                    message.hashlock,
                    message.sender,
                )

                self.raiden.state_machine_event_handler.dispatch_by_identifier(
                    message.identifier,
                    state_change,
                )

    def message_secret(self, message):
        # notify the waiting tasks about the message (multiple tasks could
        # happen in exchanges were a node is on both token transfers), and make
        # sure that the secret is register if it fails (or it has exited
        # because the transfer was considered done)
        try:
            self.raiden.message_for_task(message, message.hashlock)
        finally:
            try:
                # register the secret with all channels interested in it (this
                # must not withdraw or unlock otherwise the state changes could
                # flow in the wrong order in the path)
                self.raiden.register_secret(message.secret)

                secret = message.secret
                identifier = message.identifier
                token = message.token
                secret = message.secret
                hashlock = sha3(secret)

                self.raiden.handle_secret(
                    identifier,
                    token,
                    secret,
                    message,
                    hashlock,
                )
            except:  # pylint: disable=bare-except
                log.exception('Unhandled exception')

        if message.identifier in self.raiden.identifier_statemanager:
            state_change = ReceiveSecretReveal(
                message.secret,
                message.sender,
            )

            self.raiden.state_machine_event_handler.dispatch_by_identifier(
                message.identifier,
                state_change,
            )

    def message_refundtransfer(self, message):
        # compat: dispatch to existing tasks
        self.raiden.message_for_task(message, message.lock.hashlock)

        if message.identifier in self.raiden.identifier_statemanager:
            identifier = message.identifier
            token_address = message.token
            target = message.target
            amount = message.lock.amount
            expiration = message.lock.expiration
            hashlock = message.lock.hashlock

            manager = self.raiden.identifier_statemanager[identifier]

            if isinstance(manager.current_state, InitiatorState):
                initiator_address = self.raiden.address

            elif isinstance(manager.current_state, MediatorState):
                last_pair = manager.current_state.transfers_pair[-1]
                initiator_address = last_pair.payee_transfer.initiator

            else:
                # TODO: emit a proper event for the reject message
                return

            transfer_state = LockedTransferState(
                identifier=identifier,
                amount=amount,
                token=token_address,
                initiator=initiator_address,
                target=target,
                expiration=expiration,
                hashlock=hashlock,
                secret=None,
            )
            state_change = ReceiveTransferRefund(
                message.sender,
                transfer_state,
            )
            self.raiden.state_machine_event_handler.dispatch_by_identifier(
                message.identifier,
                state_change,
            )

    def message_directtransfer(self, message):
        if message.token not in self.raiden.channelgraphs:
            raise UnknownTokenAddress('Unknow token address {}'.format(pex(message.token)))

        graph = self.raiden.channelgraphs[message.token]

        if not graph.has_channel(self.raiden.address, message.sender):
            raise UnknownAddress(
                'Direct transfer from node without an existing channel: {}'.format(
                    pex(message.sender),
                )
            )

        channel = graph.partneraddress_channel[message.sender]

        if not channel.isopen:
            raise TransferWhenClosed(
                'Direct transfer received for a closed channel: {}'.format(
                    pex(channel.channel_address),
                )
            )

        channel.register_transfer(message)

    def message_mediatedtransfer(self, message):
        # TODO: reject mediated transfer that the hashlock/identifier is known,
        # this is a downstream bug and the transfer is going in cycles

        token_address = message.token
        graph = self.raiden.channelgraphs[message.token]

        if not graph.has_channel(self.raiden.address, message.sender):
            raise UnknownAddress(
                'Direct transfer from node without an existing channel: {}'.format(
                    pex(message.sender),
                )
            )

        channel = graph.partneraddress_channel[message.sender]

        if not channel.isopen:
            raise TransferWhenClosed(
                'Direct transfer received for a closed channel: {}'.format(
                    pex(channel.channel_address),
                )
            )

        channel.register_transfer(message)  # raises if the message is invalid

        if message.target == self.raiden.address:
            try:
                self.raiden.message_for_task(
                    message,
                    message.lock.hashlock
                )
            except UnknownAddress:
                # assumes that the registered task(s) tooks care of the message
                # (used for exchanges)
                secret_request_task = EndMediatedTransferTask(
                    self.raiden,
                    token_address,
                    message,
                )
                secret_request_task.start()

        else:
            self.raiden.mediate_mediated_transfer(message)


class StateMachineEventHandler(object):
    def __init__(self, raiden):
        self.raiden = raiden

    def dispatch_to_all_tasks(self, state_change):
        manager_lists = self.raiden.identifier_statemanager.itervalues()

        for manager in itertools.chain(*manager_lists):
            self.dispatch(manager, state_change)

    def dispatch_by_identifier(self, identifier, state_change):
        manager_list = self.raiden.identifier_statemanager[identifier]

        for manager in manager_list:
            self.dispatch(manager, state_change)

    def dispatch(self, state_manager, state_change):
        all_events = state_manager.dispatch(state_change)

        for event in all_events:
            self.on_event(event)

    def on_event(self, event):
        if isinstance(event, SendMediatedTransfer):
            next_hop = event.node_address
            fee = 0

            graph = self.raiden.channelgraphs[event.token]
            channel = graph.partneraddress_channel[next_hop]

            mediated_transfer = channel.create_mediatedtransfer(
                event.initiator,
                event.target,
                fee,
                event.amount,
                event.identifier,
                event.expiration,
                event.hashlock,
            )

            self.raiden.sign(mediated_transfer)
            channel.register_transfer(mediated_transfer)
            self.raiden.send_async(next_hop, mediated_transfer)

        elif isinstance(event, SendRevealSecret):
            reveal_message = RevealSecret(event.secret)
            self.raiden.sign(reveal_message)
            self.raiden.send_async(event.receiver, reveal_message)

        elif isinstance(event, SendBalanceProof):
            # TODO: issue #189
            secret_message = Secret(
                event.identifier,
                event.secret,
                event.token,
            )
            self.raiden.sign(secret_message)
            self.raiden.send_async(event.receiver, secret_message)

        elif isinstance(event, SendSecretRequest):
            pass

        elif isinstance(event, SendRefundTransfer):
            pass

        elif isinstance(event, EventTransferCompleted):
            for result in self.raiden.identifier_result[event.identifier]:
                result.set(True)

        elif isinstance(event, EventTransferFailed):
            for result in self.raiden.identifier_result[event.identifier]:
                result.set(True)

    def on_blockchain_statechange(self, state_change):
        if log.isEnabledFor(logging.INFO):
            log.info('state_change received', state_change=state_change)

        if isinstance(state_change, ContractReceiveTokenAdded):
            self.handle_tokenadded(state_change)

        if isinstance(state_change, ContractReceiveNewChannel):
            self.handle_channelnew(state_change)

        if isinstance(state_change, ContractReceiveBalance):
            self.handle_balance(state_change)

        if isinstance(state_change, ContractReceiveClosed):
            self.handle_closed(state_change)

        if isinstance(state_change, ContractReceiveSettled):
            self.handle_settled(state_change)

        if isinstance(state_change, ContractReceiveWithdraw):
            self.handle_withdraw(state_change)

        else:
            if log.isEnabledFor(logging.ERROR):
                log.error('Unknown state_change', state_change=state_change)

    def handle_tokenadded(self, state_change):
        manager_address = state_change.manager_address
        self.raiden.register_channel_manager(manager_address)

    def handle_channelnew(self, state_change):
        manager_address = state_change.manager_address
        channel_address = state_change.channel_address
        participant1 = state_change.participant1
        participant2 = state_change.participant2

        token_address = self.raiden.manager_token[manager_address]
        graph = self.raiden.channelgraphs[token_address]
        graph.add_path(participant1, participant2)

        if participant1 == self.raiden.address or participant2 == self.raiden.address:
            self.raiden.register_netting_channel(
                token_address,
                channel_address,
            )

    def handle_balance(self, state_change):
        channel_address = state_change.channel_address
        token_address = state_change.token_address
        participant_address = state_change.participant_address
        balance = state_change.balance
        block_number = state_change.block_number

        graph = self.raiden.channelgraphs[token_address]
        channel = graph.address_channel[channel_address]
        channel_state = channel.get_state_for(participant_address)

        if channel_state.contract_balance != balance:
            channel_state.update_contract_balance(balance)

        if channel.external_state.opened_block == 0:
            channel.external_state.set_opened(block_number)

    def handle_closed(self, state_change):
        channel_address = state_change.channel_address
        block_number = state_change.block_number

        channel = self.raiden.find_channel_by_address(channel_address)
        channel.external_state.set_closed(block_number)

    def handle_settled(self, state_change):
        channel_address = state_change.channel_address
        block_number = state_change.block_number

        channel = self.raiden.find_channel_by_address(channel_address)
        channel.external_state.set_settled(block_number)

    def handle_withdraw(self, state_change):
        secret = state_change.secret
        self.raiden.register_secret(secret)
