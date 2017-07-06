# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines
import os
from os import path
import itertools
import cPickle as pickle
import random
from collections import defaultdict

import gevent
from gevent.event import AsyncResult
from coincurve import PrivateKey
from ethereum import slogging
from ethereum.utils import encode_hex

from raiden.constants import (
    UINT64_MAX,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MIN,
)
from raiden.blockchain.events import (
    get_relevant_proxies,
    PyethappBlockchainEvents,
)
from raiden.event_handler import StateMachineEventHandler
from raiden.message_handler import RaidenMessageHandler
from raiden.tasks import (
    AlarmTask,
)
from raiden.token_swap import GreenletTasksDispatcher
from raiden.transfer.architecture import StateManager
from raiden.transfer.state_change import Block
from raiden.transfer.state import (
    RoutesState,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
)
from raiden.transfer.mediated_transfer import (
    initiator,
    mediator,
)
from raiden.transfer.mediated_transfer import target as target_task
from raiden.transfer.mediated_transfer.state import (
    lockedtransfer_from_message,
    LockedTransferState,
)
from raiden.transfer.state_change import (
    ActionTransferDirect,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ActionInitTarget,
)
from raiden.transfer.events import (
    EventTransferSentSuccess,
)
from raiden.transfer.log import (
    StateChangeLog,
    StateChangeLogSQLiteBackend,
)
from raiden.channel import (
    ChannelEndState,
    ChannelExternalState,
)
from raiden.channel.netting_channel import (
    ChannelSerialization,
)
from raiden.exceptions import InvalidAddress
from raiden.network.channelgraph import (
    get_best_routes,
    channel_to_routestate,
    route_to_routestate,
    ChannelGraph,
    ChannelDetails,
)
from raiden.messages import (
    RevealSecret,
    Secret,
    SignedMessage,
)
from raiden.network.protocol import (
    RaidenProtocol,
)
from raiden.connection_manager import ConnectionManager
from raiden.utils import (
    isaddress,
    pex,
    privatekey_to_address,
    sha3,
)

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


def create_default_identifier():
    """ Generates a random identifier. """
    return random.randint(0, UINT64_MAX)


class RandomSecretGenerator(object):  # pylint: disable=too-few-public-methods
    def __next__(self):  # pylint: disable=no-self-use
        return os.urandom(32)

    next = __next__


class RaidenService(object):
    """ A Raiden node. """
    # pylint: disable=too-many-instance-attributes,too-many-public-methods

    def __init__(self, chain, private_key_bin, transport, discovery, config):
        if not isinstance(private_key_bin, bytes) or len(private_key_bin) != 32:
            raise ValueError('invalid private_key')

        if config['settle_timeout'] < NETTINGCHANNEL_SETTLE_TIMEOUT_MIN:
            raise ValueError('settle_timeout must be larger-or-equal to {}'.format(
                NETTINGCHANNEL_SETTLE_TIMEOUT_MIN
            ))

        private_key = PrivateKey(private_key_bin)
        pubkey = private_key.public_key.format(compressed=False)
        protocol = RaidenProtocol(
            transport,
            discovery,
            self,
            config['protocol']['retry_interval'],
            config['protocol']['retries_before_backoff'],
            config['protocol']['nat_keepalive_retries'],
            config['protocol']['nat_keepalive_timeout'],
            config['protocol']['nat_invitation_timeout'],
        )
        transport.protocol = protocol

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
        self.protocol = protocol

        message_handler = RaidenMessageHandler(self)
        state_machine_event_handler = StateMachineEventHandler(self)
        pyethapp_blockchain_events = PyethappBlockchainEvents()
        greenlet_task_dispatcher = GreenletTasksDispatcher()

        alarm = AlarmTask(chain)

        # prime the block number cache and set the callbacks
        self._blocknumber = alarm.last_block_number
        alarm.register_callback(lambda _: self.poll_blockchain_events())
        alarm.register_callback(self.set_block_number)

        self.transaction_log = StateChangeLog(
            storage_instance=StateChangeLogSQLiteBackend(
                database_path=config['database_path']
            )
        )

        alarm.start()

        registry_event = gevent.spawn(
            discovery.register,
            self.address,
            config['external_ip'],
            config['external_port'],
        )

        self.channels_serialization_path = None
        self.channels_queue_path = None
        self.transfer_states_path = None

        self.alarm = alarm
        self.message_handler = message_handler
        self.state_machine_event_handler = state_machine_event_handler
        self.pyethapp_blockchain_events = pyethapp_blockchain_events
        self.greenlet_task_dispatcher = greenlet_task_dispatcher

        self.on_message = message_handler.on_message

        self.tokens_connectionmanagers = dict()  # token_address: ConnectionManager

        if config['database_path'] != ':memory:':
            snapshot_dir = path.join(
                path.dirname(self.config['database_path']),
                pex(self.address)
            )
            if not os.path.exists(snapshot_dir):
                os.makedirs(
                    snapshot_dir
                )

            self.channels_serialization_path = path.join(
                snapshot_dir,
                'channels.pickle',
            )

            self.channels_queue_path = path.join(
                snapshot_dir,
                'queues.pickle',
            )
            self.transfer_states_path = path.join(
                snapshot_dir,
                'transfer_states.pickle',
            )
            self.register_registry(self.chain.default_registry.address)
            self.restore_from_snapshots()

            registry_event.join()

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.address))

    def restore_from_snapshots(self):
        if path.exists(self.channels_serialization_path):
            serialized_channels = list()

            with open(self.channels_serialization_path, 'rb') as handler:
                try:
                    while True:
                        serialized_channels.append(pickle.load(handler))
                except EOFError:
                    pass

            for channel in serialized_channels:
                self.restore_channel(channel)

        if path.exists(self.channels_queue_path):
            with open(self.channels_queue_path, 'rb') as handler:
                channel_state = pickle.load(handler)

            for restored_queue in channel_state['channel_queues']:
                self.restore_queue(restored_queue)

            self.protocol.receivedhashes_to_acks = channel_state['receivedhashes_to_acks']
            self.protocol.nodeaddresses_to_nonces = channel_state['nodeaddresses_to_nonces']

        if path.exists(self.transfer_states_path):
            with open(self.transfer_states_path, 'rb') as handler:
                transfer_states = pickle.load(handler)

            self.restore_transfer_states(transfer_states)

    def set_block_number(self, blocknumber):
        state_change = Block(blocknumber)
        self.state_machine_event_handler.log_and_dispatch_to_all_tasks(state_change)

        for graph in self.channelgraphs.itervalues():
            for channel in graph.address_channel.itervalues():
                channel.state_transition(state_change)

        # To avoid races, only update the internal cache after all the state
        # tasks have been updated.
        self._blocknumber = blocknumber

    def set_node_network_state(self, node_address, network_state):
        for graph in self.channelgraphs.itervalues():
            channel = graph.partneraddress_channel.get(node_address)

            if channel:
                channel.network_state = network_state

    def start_health_check_for(self, node_address):
        self.protocol.start_health_check(node_address)

    def get_block_number(self):
        return self._blocknumber

    def poll_blockchain_events(self):
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

        if not channels_list:
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

    def restore_channel(self, serialized_channel):
        token_address = serialized_channel.token_address

        netting_channel = self.chain.netting_channel(
            serialized_channel.channel_address,
        )

        # restoring balances from the BC since the serialized value could be
        # falling behind.
        channel_details = netting_channel.detail(self.address)

        # our_address is checked by detail
        assert channel_details['partner_address'] == serialized_channel.partner_address

        opened_block = netting_channel.opened()
        our_state = ChannelEndState(
            channel_details['our_address'],
            channel_details['our_balance'],
            opened_block,
        )
        partner_state = ChannelEndState(
            channel_details['partner_address'],
            channel_details['partner_balance'],
            opened_block,
        )

        def register_channel_for_hashlock(channel, hashlock):
            self.register_channel_for_hashlock(
                token_address,
                channel,
                hashlock,
            )

        external_state = ChannelExternalState(
            register_channel_for_hashlock,
            netting_channel,
        )
        details = ChannelDetails(
            serialized_channel.channel_address,
            our_state,
            partner_state,
            external_state,
            serialized_channel.reveal_timeout,
            channel_details['settle_timeout'],
        )

        graph = self.channelgraphs[token_address]
        graph.add_channel(details, serialized_channel.block_number)
        channel = graph.address_channel.get(
            serialized_channel.channel_address,
        )

        channel.our_state.balance_proof = serialized_channel.our_balance_proof
        channel.partner_state.balance_proof = serialized_channel.partner_balance_proof

        # `register_channel_for_hashlock` is deprecated, currently only the
        # swap tasks are using it and these tasks are /not/ restartable, there
        # is no point in re-registering the hashlocks.
        #
        # all_hashlocks = itertools.chain(
        #     serialized_channel.our_balance_proof.hashlock_pendinglocks.keys(),
        #     serialized_channel.our_balance_proof.hashlock_unclaimedlocks.keys(),
        #     serialized_channel.our_balance_proof.hashlock_unlockedlocks.keys(),
        #     serialized_channel.partner_balance_proof.hashlock_pendinglocks.keys(),
        #     serialized_channel.partner_balance_proof.hashlock_unclaimedlocks.keys(),
        #     serialized_channel.partner_balance_proof.hashlock_unlockedlocks.keys(),
        # )
        # for hashlock in all_hashlocks:
        #     register_channel_for_hashlock(channel, hashlock)

    def restore_queue(self, serialized_queue):
        receiver_address = serialized_queue['receiver_address']
        token_address = serialized_queue['token_address']

        queue = self.protocol.get_channel_queue(
            receiver_address,
            token_address,
        )

        for messagedata in serialized_queue['messages']:
            queue.put(messagedata)

    def restore_transfer_states(self, transfer_states):
        self.identifier_to_statemanagers = transfer_states

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

    def leave_all_token_networks_async(self):
        token_addresses = self.channelgraphs.keys()
        leave_results = []
        for token_address in token_addresses:
            try:
                connection_manager = self.connection_manager_for_token(token_address)
            except InvalidAddress:
                pass
            leave_results.append(connection_manager.leave_async())
        combined_result = AsyncResult()
        gevent.spawn(gevent.wait, leave_results).link(combined_result)
        return combined_result

    def close_and_settle(self):
        log.info('raiden will close and settle all channels now')

        connection_managers = [
            self.connection_manager_for_token(token_address) for
            token_address in self.channelgraphs
        ]

        def blocks_to_wait():
            return max(
                connection_manager.min_settle_blocks
                for connection_manager in connection_managers
            )

        all_channels = list(
            itertools.chain.from_iterable(
                [connection_manager.open_channels for connection_manager in connection_managers]
            )
        )

        leaving_greenlet = self.leave_all_token_networks_async()
        # using the un-cached block number here
        last_block = self.chain.block_number()

        earliest_settlement = last_block + blocks_to_wait()

        # TODO: estimate and set a `timeout` parameter in seconds
        # based on connection_manager.min_settle_blocks and an average
        # blocktime from the past

        current_block = last_block
        avg_block_time = self.chain.estimate_blocktime()
        wait_blocks_left = blocks_to_wait()
        while current_block < earliest_settlement:
            gevent.sleep(self.alarm.wait_time)
            last_block = self.chain.block_number()
            if last_block != current_block:
                current_block = last_block
                avg_block_time = self.chain.estimate_blocktime()
                wait_blocks_left = blocks_to_wait()
                not_settled = sum(
                    1 for channel in all_channels
                    if not channel.state == CHANNEL_STATE_SETTLED
                )
                if not_settled == 0:
                    log.debug('nothing left to settle')
                    break
                log.info(
                    'waiting at least %s more blocks (~%s sec) for settlement'
                    '(%s channels not yet settled)' % (
                        wait_blocks_left,
                        wait_blocks_left * avg_block_time,
                        not_settled
                    )
                )

            leaving_greenlet.wait(timeout=blocks_to_wait() * self.chain.estimate_blocktime() * 1.5)

        if any(channel.state != CHANNEL_STATE_SETTLED for channel in all_channels):
            log.error(
                'Some channels were not settled!',
                channels=[
                    pex(channel.channel_address) for channel in all_channels
                    if channel.state != CHANNEL_STATE_SETTLED
                ]
            )

    def stop(self):
        wait_for = [self.alarm]
        wait_for.extend(self.greenlet_task_dispatcher.stop())

        self.alarm.stop_async()

        wait_for.extend(self.protocol.greenlets)
        self.pyethapp_blockchain_events.uninstall_all_event_listeners()

        self.protocol.stop_and_wait()

        self.store_state()

        gevent.wait(wait_for)

    def store_state(self):
        if self.channels_serialization_path:
            with open(self.channels_serialization_path, 'wb') as handler:
                for network in self.channelgraphs.values():
                    for channel in network.address_channel.values():
                        pickle.dump(
                            ChannelSerialization(channel),
                            handler,
                            protocol=-1  # __slots__ without __getstate__ require `-1`
                        )

        if self.channels_queue_path:
            with open(self.channels_queue_path, 'wb') as handler:
                queues = list()
                for key, queue in self.protocol.channel_queue.iteritems():
                    queue_data = {
                        'receiver_address': key[0],
                        'token_address': key[1],
                        'messages': [
                            queue_item for queue_item in queue.snapshot()
                        ]
                    }
                    queues.append(queue_data)

                pickle.dump(
                    {
                        'channel_queues': queues,
                        'receivedhashes_to_acks': self.protocol.receivedhashes_to_acks,
                        'nodeaddresses_to_nonces': self.protocol.nodeaddresses_to_nonces,
                    },
                    handler,
                    protocol=-1  # __slots__ without __getstate__ require `-1`
                )

        if self.transfer_states_path:
            # ensure that all state managers are unique
            assert (
                len(
                    set(itertools.chain.from_iterable(self.identifier_to_statemanagers.values()))
                ) == sum(
                    len(state_managers)
                    for state_managers in self.identifier_to_statemanagers.values()
                )
            )
            with open(self.transfer_states_path, 'wb') as handler:
                pickle.dump(
                    self.identifier_to_statemanagers,
                    handler,
                    protocol=-1  # __slots__ without __getstate__ require `-1`
                )

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
            identifier = create_default_identifier()

        direct_channel = graph.partneraddress_channel.get(target)
        if direct_channel:
            async_result = self._direct_or_mediated_transfer(
                token_address,
                amount,
                identifier,
                direct_channel,
            )
            return async_result

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

        if not direct_channel.can_transfer:
            log.info(
                'DIRECT CHANNEL %s > %s is closed or has no funding',
                pex(direct_channel.our_state.address),
                pex(direct_channel.partner_state.address),
            )

            async_result = self._mediated_transfer(
                token_address,
                amount,
                identifier,
                direct_channel.partner_state.address,
            )

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

        else:
            direct_transfer = direct_channel.create_directtransfer(amount, identifier)
            self.sign(direct_transfer)
            direct_channel.register_transfer(
                self.get_block_number(),
                direct_transfer,
            )

            direct_transfer_state_change = ActionTransferDirect(
                identifier,
                amount,
                token_address,
                direct_channel.partner_state.address,
            )
            # TODO: add the transfer sent event
            state_change_id = self.transaction_log.log(direct_transfer_state_change)

            # TODO: This should be set once the direct transfer is acknowledged
            transfer_success = EventTransferSentSuccess(
                identifier,
            )
            self.transaction_log.log_events(
                state_change_id,
                [transfer_success],
                self.get_block_number()
            )

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
        routes = get_best_routes(
            graph,
            self.protocol.nodeaddresses_networkstatuses,
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

        self.protocol.start_health_check(target)

        if identifier is None:
            identifier = create_default_identifier()

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
        routes = get_best_routes(
            graph,
            self.protocol.nodeaddresses_networkstatuses,
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
