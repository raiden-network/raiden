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

from coincurve import PrivateKey

from raiden.constants import UINT64_MAX
from raiden.blockchain.events import (
    get_relevant_proxies,
    PyethappBlockchainEvents,
)
from raiden.tasks import (
    AlarmTask,
    HealthcheckTask,
)
from raiden.token_swap import (
    GreenletTasksDispatcher,
    SwapKey,
    TakerTokenSwapTask,
)
from raiden.transfer.architecture import (
    StateManager,
)
from raiden.transfer.state_change import (
    Block,
)
from raiden.transfer.state import (
    RoutesState,
    CHANNEL_STATE_OPENED,
)
from raiden.transfer.mediated_transfer import (
    initiator,
    mediator,
)
from raiden.transfer.mediated_transfer import target as target_task
from raiden.transfer.mediated_transfer.state import (
    lockedtransfer_from_message,
    InitiatorState,
    MediatorState,
    LockedTransferState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ActionInitTarget,
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
from raiden.transfer.log import (
    StateChangeLog,
    StateChangeLogSQLiteBackend,
)
from raiden.channel import ChannelEndState, ChannelExternalState
from raiden.exceptions import (
    UnknownAddress,
    TransferWhenClosed,
    UnknownTokenAddress,
    InvalidAddress,
)
from raiden.network.channelgraph import (
    channel_to_routestate,
    route_to_routestate,
    ChannelGraph,
    ChannelDetails,
)
from raiden.encoding import messages
from raiden.messages import (
    RevealSecret,
    Secret,
    SecretRequest,
    SignedMessage,
)
from raiden.network.protocol import RaidenProtocol
from raiden.connection_manager import ConnectionManager
from raiden.utils import (
    isaddress,
    pex,
    privatekey_to_address,
    sha3,
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
    hash_ = sha3('{}{}{}{}'.format(
        node_address,
        target,
        token_address,
        random.randint(0, UINT64_MAX)
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
        if not isinstance(private_key_bin, bytes) or len(private_key_bin) != 32:
            raise ValueError('invalid private_key')

        private_key = PrivateKey(private_key_bin)
        pubkey = private_key.public_key.format(compressed=False)

        self.channelgraphs = dict()
        self.manager_token = dict()
        self.swapkeys_tokenswaps = dict()
        self.swapkeys_greenlettasks = dict()

        self.identifier_to_statemanagers = defaultdict(list)
        self.identifier_to_results = defaultdict(list)

        # This is a map from a hashlock to a list of channels, the same
        # hashlock can be used in more than one token (for tokenswaps), a
        # channel should be removed from this list only when the lock is
        # released/withdrawn but not when the secret is registered.
        self.tokens_hashlocks_channels = defaultdict(lambda: defaultdict(list))

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
        greenlet_task_dispatcher = GreenletTasksDispatcher()

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

        self.transaction_log = StateChangeLog(
            storage_instance=StateChangeLogSQLiteBackend(
                database_path=config['database_path']
            )
        )
        self.alarm = alarm
        self.message_handler = message_handler
        self.state_machine_event_handler = state_machine_event_handler
        self.pyethapp_blockchain_events = pyethapp_blockchain_events
        self.greenlet_task_dispatcher = greenlet_task_dispatcher

        self.on_message = message_handler.on_message

        self.tokens_connectionmanagers = dict()  # token_address: ConnectionManager

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.address))

    def set_block_number(self, blocknumber):
        self._blocknumber = blocknumber

        state_change = Block(blocknumber)
        self.state_machine_event_handler.dispatch_to_all_tasks(state_change)

        for graph in self.channelgraphs.itervalues():
            for channel in graph.address_channel.itervalues():
                channel.state_transition(state_change)

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

    def register_secret(self, secret):
        """ Register the secret with any channel that has a hashlock on it.

        This must search through all channels registered for a given hashlock
        and ignoring the tokens. Useful for refund transfer, split transfer,
        and token swaps.
        """
        hashlock = sha3(secret)
        revealsecret_message = RevealSecret(secret)
        self.sign(revealsecret_message)

        for hash_channel in self.tokens_hashlocks_channels.itervalues():
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
                    # point, nevertheless handle it because we dont want an
                    # error in a channel to mess the state from others.
                    log.error('programming error')

    def register_channel_for_hashlock(self, token_address, channel, hashlock):
        channels_registered = self.tokens_hashlocks_channels[token_address][hashlock]

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
        channels_list = self.tokens_hashlocks_channels[token_address][hashlock]
        channels_to_remove = list()

        # Dont use the partner_secret_message.token since it might not match
        # the current token manager
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
                    matching_sender = (
                        partner_secret_message.sender == channel.partner_state.address
                    )
                    matching_token = partner_secret_message.token == channel.token_address

                    if matching_sender and matching_token:
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
            del self.tokens_hashlocks_channels[token_address][hashlock]

    def get_channel_details(self, token_address, netting_channel):
        channel_details = netting_channel.detail(self.address)
        our_state = ChannelEndState(
            channel_details['our_address'],
            channel_details['our_balance'],
            netting_channel.opened(),
        )
        partner_state = ChannelEndState(
            channel_details['partner_address'],
            channel_details['partner_balance'],
            netting_channel.opened(),
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
            register_channel_for_hashlock,
            netting_channel,
        )

        channel_detail = ChannelDetails(
            channel_address,
            our_state,
            partner_state,
            external_state,
            reveal_timeout,
            settle_timeout,
        )

        return channel_detail

    def register_registry(self, registry_address):
        proxies = get_relevant_proxies(
            self.chain,
            self.address,
            registry_address,
        )

        # Install the filters first to avoid missing changes, as a consequence
        # some events might be applied twice.
        self.pyethapp_blockchain_events.add_proxies_listeners(proxies)

        block_number = self.get_block_number()

        for manager in proxies.channel_managers:
            token_address = manager.token_address()
            manager_address = manager.address

            channels_detail = list()
            netting_channels = proxies.channelmanager_nettingchannels[manager_address]
            for channel in netting_channels:
                detail = self.get_channel_details(token_address, channel)
                channels_detail.append(detail)

            edge_list = manager.channels_addresses()
            graph = ChannelGraph(
                self.address,
                manager_address,
                token_address,
                edge_list,
                channels_detail,
                block_number,
            )

            self.manager_token[manager_address] = token_address
            self.channelgraphs[token_address] = graph

            self.tokens_connectionmanagers[token_address] = ConnectionManager(
                self,
                token_address,
                graph
            )

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
            self.get_channel_details(token_address, channel)
            for channel in netting_channels
        ]

        block_number = self.get_block_number()
        graph = ChannelGraph(
            self.address,
            manager_address,
            token_address,
            edge_list,
            channels_detail,
            block_number,
        )

        self.manager_token[manager_address] = token_address
        self.channelgraphs[token_address] = graph

        self.tokens_connectionmanagers[token_address] = ConnectionManager(
            self,
            token_address,
            graph
        )

    def register_netting_channel(self, token_address, channel_address):
        netting_channel = self.chain.netting_channel(channel_address)
        self.pyethapp_blockchain_events.add_netting_channel_listener(netting_channel)

        block_number = self.get_block_number()
        detail = self.get_channel_details(token_address, netting_channel)
        graph = self.channelgraphs[token_address]
        graph.add_channel(detail, block_number)

    def connection_manager_for_token(self, token_address):
        if not isaddress(token_address):
            raise InvalidAddress('token address is not valid.')
        if token_address in self.tokens_connectionmanagers.keys():
            manager = self.tokens_connectionmanagers[token_address]
        else:
            raise InvalidAddress('token is not registered.')
        return manager

    def stop(self):
        wait_for = [self.alarm]

        wait_for.extend(self.greenlet_task_dispatcher.stop())

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
            - Network speed, making the transfer sufficiently fast so it doesn't
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
            if route.state == CHANNEL_STATE_OPENED
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

        # Issue #489
        #
        # Raiden may fail after a state change using the random generator is
        # handled but right before the snapshot is taken. If that happens on
        # the next initialization when raiden is recovering and applying the
        # pending state changes a new secret will be generated and the
        # resulting events won't match, this breaks the architecture model,
        # since it's assumed the re-execution of a state change will always
        # produce the same events.
        #
        # TODO: Removed the secret generator from the InitiatorState and add
        # the secret into all state changes that require one, this way the
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
        self.state_machine_event_handler.log_and_dispatch(state_manager, init_initiator)
        async_result = AsyncResult()

        # TODO: implement the network timeout raiden.config['msg_timeout'] and
        # cancel the current transfer if it hapens (issue #374)
        self.identifier_to_statemanagers[identifier].append(state_manager)
        self.identifier_to_results[identifier].append(async_result)

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
            if route.state == CHANNEL_STATE_OPENED
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
        self.state_machine_event_handler.log_and_dispatch(state_manager, init_mediator)

        self.identifier_to_statemanagers[identifier].append(state_manager)

    def target_mediated_transfer(self, message):
        graph = self.channelgraphs[message.token]
        from_channel = graph.partneraddress_channel[message.sender]
        from_route = channel_to_routestate(from_channel, message.sender)

        from_transfer = lockedtransfer_from_message(message)
        our_address = self.address
        block_number = self.get_block_number()

        init_target = ActionInitTarget(
            our_address,
            from_route,
            from_transfer,
            block_number,
        )

        state_manager = StateManager(target_task.state_transition, None)
        self.state_machine_event_handler.log_and_dispatch(state_manager, init_target)

        identifier = message.identifier
        self.identifier_to_statemanagers[identifier].append(state_manager)


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
        secret = message.secret
        sender = message.sender

        self.raiden.greenlet_task_dispatcher.dispatch_message(
            message,
            message.hashlock,
        )
        self.raiden.register_secret(secret)

        state_change = ReceiveSecretReveal(secret, sender)
        self.raiden.state_machine_event_handler.dispatch_to_all_tasks(state_change)

    def message_secretrequest(self, message):
        self.raiden.greenlet_task_dispatcher.dispatch_message(
            message,
            message.hashlock,
        )

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
        self.raiden.greenlet_task_dispatcher.dispatch_message(
            message,
            message.hashlock,
        )

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

        state_change = ReceiveSecretReveal(
            message.secret,
            message.sender,
        )

        self.raiden.state_machine_event_handler.dispatch_by_identifier(
            message.identifier,
            state_change,
        )

    def message_refundtransfer(self, message):
        self.raiden.greenlet_task_dispatcher.dispatch_message(
            message,
            message.lock.hashlock,
        )

        identifier = message.identifier
        token_address = message.token
        target = message.target
        amount = message.lock.amount
        expiration = message.lock.expiration
        hashlock = message.lock.hashlock

        manager = self.raiden.identifier_to_statemanagers[identifier]

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
            raise UnknownTokenAddress('Unknown token address {}'.format(pex(message.token)))

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
        # TODO: Reject mediated transfer that the hashlock/identifier is known,
        # this is a downstream bug and the transfer is going in cycles (issue #490)

        key = SwapKey(
            message.identifier,
            message.token,
            message.lock.amount,
        )

        # TODO: add a separate message for token swaps to simplify message
        # handling (issue #487)
        if key in self.raiden.swapkeys_tokenswaps:
            self.message_tokenswap(message)
            return

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
            self.raiden.target_mediated_transfer(message)

        else:
            self.raiden.mediate_mediated_transfer(message)

    def message_tokenswap(self, message):
        key = SwapKey(
            message.identifier,
            message.token,
            message.lock.amount,
        )

        # If we are the maker the task is already running and waiting for the
        # taker's MediatedTransfer
        task = self.raiden.swapkeys_greenlettasks.get(key)
        if task:
            task.response_queue.put(message)

        # If we are the taker we are receiving the maker transfer and should
        # start our new task
        else:
            token_swap = self.raiden.swapkeys_tokenswaps[key]
            task = TakerTokenSwapTask(
                self.raiden,
                token_swap,
                message,
            )
            task.start()

            self.raiden.swapkeys_greenlettasks[key] = task


class StateMachineEventHandler(object):
    def __init__(self, raiden):
        self.raiden = raiden

    def dispatch_to_all_tasks(self, state_change):
        self.raiden.transaction_log.log(state_change)
        manager_lists = self.raiden.identifier_to_statemanagers.itervalues()

        for manager in itertools.chain(*manager_lists):
            self.dispatch(manager, state_change)

    def dispatch_by_identifier(self, identifier, state_change):
        self.raiden.transaction_log.log(state_change)
        manager_list = self.raiden.identifier_to_statemanagers[identifier]

        for manager in manager_list:
            self.dispatch(manager, state_change)

    def log_and_dispatch(self, state_manager, state_change):
        self.raiden.transaction_log.log(state_change)
        self.dispatch(state_manager, state_change)

    def dispatch(self, state_manager, state_change):
        all_events = state_manager.dispatch(state_change)

        for event in all_events:
            self.on_event(event)

    def on_event(self, event):
        if isinstance(event, SendMediatedTransfer):
            receiver = event.receiver
            fee = 0
            graph = self.raiden.channelgraphs[event.token]
            channel = graph.partneraddress_channel[receiver]

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
            self.raiden.send_async(receiver, mediated_transfer)

        elif isinstance(event, SendRevealSecret):
            reveal_message = RevealSecret(event.secret)
            self.raiden.sign(reveal_message)
            self.raiden.send_async(event.receiver, reveal_message)

        elif isinstance(event, SendBalanceProof):
            # TODO: issue #189

            # unlock and update remotely (send the Secret message)
            self.raiden.handle_secret(
                event.identifier,
                event.token,
                event.secret,
                None,
                sha3(event.secret),
            )

        elif isinstance(event, SendSecretRequest):
            secret_request = SecretRequest(
                event.identifier,
                event.hashlock,
                event.amount,
            )
            self.raiden.sign(secret_request)
            self.raiden.send_async(event.receiver, secret_request)

        elif isinstance(event, SendRefundTransfer):
            pass

        elif isinstance(event, EventTransferCompleted):
            for result in self.raiden.identifier_to_results[event.identifier]:
                result.set(True)

        elif isinstance(event, EventTransferFailed):
            for result in self.raiden.identifier_to_results[event.identifier]:
                result.set(True)

    def on_blockchain_statechange(self, state_change):
        if log.isEnabledFor(logging.INFO):
            log.info('state_change received', state_change=state_change)
        self.raiden.transaction_log.log(state_change)

        if isinstance(state_change, ContractReceiveTokenAdded):
            self.handle_tokenadded(state_change)

        elif isinstance(state_change, ContractReceiveNewChannel):
            self.handle_channelnew(state_change)

        elif isinstance(state_change, ContractReceiveBalance):
            self.handle_balance(state_change)

        elif isinstance(state_change, ContractReceiveClosed):
            self.handle_closed(state_change)

        elif isinstance(state_change, ContractReceiveSettled):
            self.handle_settled(state_change)

        elif isinstance(state_change, ContractReceiveWithdraw):
            self.handle_withdraw(state_change)

        elif log.isEnabledFor(logging.ERROR):
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

        connection_manager = self.raiden.connection_manager_for_token(token_address)

        if participant1 == self.raiden.address or participant2 == self.raiden.address:
            self.raiden.register_netting_channel(
                token_address,
                channel_address,
            )
        elif connection_manager.wants_more_channels:
            gevent.spawn(connection_manager.retry_connect)
        else:
            log.info('ignoring new channel, this node is not a participant.')

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

        connection_manager = self.raiden.connection_manager_for_token(
            token_address
        )
        if channel.deposit == 0:
            gevent.spawn(
                connection_manager.join_channel,
                participant_address,
                balance
            )

        if channel.external_state.opened_block == 0:
            channel.external_state.set_opened(block_number)

    def handle_closed(self, state_change):
        channel_address = state_change.channel_address
        channel = self.raiden.find_channel_by_address(channel_address)
        channel.state_transition(state_change)

    def handle_settled(self, state_change):
        channel_address = state_change.channel_address
        channel = self.raiden.find_channel_by_address(channel_address)
        channel.state_transition(state_change)

    def handle_withdraw(self, state_change):
        secret = state_change.secret
        self.raiden.register_secret(secret)
