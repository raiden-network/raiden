# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines
import os
import sys
import itertools
import pickle as pickle
import random
from collections import defaultdict

import filelock
import gevent
from gevent.event import AsyncResult, Event
from coincurve import PrivateKey
from ethereum import slogging
from ethereum.utils import encode_hex

from raiden.constants import (
    UINT64_MAX,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MIN,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MAX,
    ROPSTEN_REGISTRY_ADDRESS,
)
from raiden.blockchain.events import (
    get_relevant_proxies,
    BlockchainEvents,
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
from raiden.exceptions import InvalidAddress, AddressWithoutCode, RaidenShuttingDown
from raiden.network.channelgraph import (
    get_best_routes,
    channel_to_routestate,
    ChannelGraph,
    ChannelDetails,
)
from raiden.messages import (
    RevealSecret,
    SignedMessage,
)
from raiden.transfer.state import MerkleTreeState
from raiden.transfer.merkle_tree import (
    EMPTY_MERKLE_TREE,
    compute_layers,
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


def load_snapshot(serialization_file):
    if os.path.exists(serialization_file):
        with open(serialization_file, 'rb') as handler:
            return pickle.load(handler)


def save_snapshot(serialization_file, raiden):
    all_channels = [
        ChannelSerialization(channel)
        for network in raiden.token_to_channelgraph.values()
        for channel in network.address_to_channel.values()
    ]

    all_queues = list()
    for key, queue in raiden.protocol.channel_queue.items():
        queue_data = {
            'receiver_address': key[0],
            'token_address': key[1],
            'messages': queue.copy(),
        }
        all_queues.append(queue_data)

    data = {
        'channels': all_channels,
        'queues': all_queues,
        'receivedhashes_to_acks': raiden.protocol.receivedhashes_to_acks,
        'nodeaddresses_to_nonces': raiden.protocol.nodeaddresses_to_nonces,
        'transfers': raiden.identifier_to_statemanagers,
        'registry_address': ROPSTEN_REGISTRY_ADDRESS,
    }

    with open(serialization_file, 'wb') as handler:
        # __slots__ without __getstate__ require `-1`
        pickle.dump(
            data,
            handler,
            protocol=-1,
        )


def endpoint_registry_exception_handler(greenlet):
    try:
        greenlet.get()
    except Exception as e:  # pylint: disable=broad-except
        rpc_unreachable = (
            e.args[0] == 'timeout when polling for transaction'
        )

        if rpc_unreachable:
            log.fatal(
                'Endpoint registry failed: %s. '
                'Ethereum RPC API might be unreachable.',
                repr(e),
            )
        else:
            log.fatal('Endpoint registry failed: %s. ', repr(e))

        sys.exit(1)


class RandomSecretGenerator:  # pylint: disable=too-few-public-methods
    def __next__(self):  # pylint: disable=no-self-use
        return os.urandom(32)

    next = __next__


class RaidenService:
    """ A Raiden node. """
    # pylint: disable=too-many-instance-attributes,too-many-public-methods

    def __init__(self, chain, default_registry, private_key_bin, transport, discovery, config):
        if not isinstance(private_key_bin, bytes) or len(private_key_bin) != 32:
            raise ValueError('invalid private_key')

        invalid_timeout = (
            config['settle_timeout'] < NETTINGCHANNEL_SETTLE_TIMEOUT_MIN or
            config['settle_timeout'] > NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
        )
        if invalid_timeout:
            raise ValueError('settle_timeout must be in range [{}, {}]'.format(
                NETTINGCHANNEL_SETTLE_TIMEOUT_MIN, NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
            ))

        self.token_to_channelgraph = dict()
        self.tokens_to_connectionmanagers = dict()
        self.manager_to_token = dict()
        self.swapkey_to_tokenswap = dict()
        self.swapkey_to_greenlettask = dict()

        self.identifier_to_statemanagers = defaultdict(list)
        self.identifier_to_results = defaultdict(list)

        # This is a map from a hashlock to a list of channels, the same
        # hashlock can be used in more than one token (for tokenswaps), a
        # channel should be removed from this list only when the lock is
        # released/withdrawn but not when the secret is registered.
        self.token_to_hashlock_to_channels = defaultdict(lambda: defaultdict(list))

        self.chain = chain
        self.default_registry = default_registry
        self.config = config
        self.privkey = private_key_bin
        self.address = privatekey_to_address(private_key_bin)

        endpoint_registration_event = gevent.spawn(
            discovery.register,
            self.address,
            config['external_ip'],
            config['external_port'],
        )
        endpoint_registration_event.link_exception(endpoint_registry_exception_handler)

        self.private_key = PrivateKey(private_key_bin)
        self.pubkey = self.private_key.public_key.format(compressed=False)
        self.protocol = RaidenProtocol(
            transport,
            discovery,
            self,
            config['protocol']['retry_interval'],
            config['protocol']['retries_before_backoff'],
            config['protocol']['nat_keepalive_retries'],
            config['protocol']['nat_keepalive_timeout'],
            config['protocol']['nat_invitation_timeout'],
        )

        # TODO: remove this cyclic dependency
        transport.protocol = self.protocol

        self.message_handler = RaidenMessageHandler(self)
        self.state_machine_event_handler = StateMachineEventHandler(self)
        self.blockchain_events = BlockchainEvents()
        self.greenlet_task_dispatcher = GreenletTasksDispatcher()
        self.on_message = self.message_handler.on_message
        self.alarm = AlarmTask(chain)
        self.shutdown_timeout = config['shutdown_timeout']
        self._block_number = None
        self.stop_event = Event()
        self.start_event = Event()
        self.chain.client.inject_stop_event(self.stop_event)

        self.transaction_log = StateChangeLog(
            storage_instance=StateChangeLogSQLiteBackend(
                database_path=config['database_path']
            )
        )

        if config['database_path'] != ':memory:':
            self.database_dir = os.path.dirname(config['database_path'])
            self.lock_file = os.path.join(self.database_dir, '.lock')
            self.snapshot_dir = os.path.join(self.database_dir, 'snapshots')
            self.serialization_file = os.path.join(self.snapshot_dir, 'data.pickle')

            if not os.path.exists(self.snapshot_dir):
                os.makedirs(self.snapshot_dir)

            # Prevent concurrent acces to the same db
            self.db_lock = filelock.FileLock(self.lock_file)
        else:
            self.database_dir = None
            self.lock_file = None
            self.snapshot_dir = None
            self.serialization_file = None
            self.db_lock = None

        # If the endpoint registration fails the node will quit, this must
        # finish before starting the protocol
        endpoint_registration_event.join()

        self.start()

    def start(self):
        """ Start the node. """
        # XXX Should this really be here? Or will start() never be called again
        # after stop() in the lifetime of Raiden apart from the tests? This is
        # at least at the moment prompted by tests/integration/test_transer.py
        if self.stop_event and self.stop_event.is_set():
            self.stop_event.clear()

        self.alarm.start()

        # Prime the block number cache and set the callbacks
        self._block_number = self.alarm.last_block_number
        self.alarm.register_callback(self.poll_blockchain_events)
        self.alarm.register_callback(self.set_block_number)

        # Registry registration must start *after* the alarm task, this avoid
        # corner cases were the registry is queried in block A, a new block B
        # is mined, and the alarm starts polling at block C.
        self.register_registry(self.default_registry.address)

        # Restore from snapshot must come after registering the registry as we
        # need to know the registered tokens to populate `token_to_channelgraph`
        if self.database_dir is not None:
            self.db_lock.acquire(timeout=0)
            assert self.db_lock.is_locked
            self.restore_from_snapshots()

        # Start the protocol after the registry is queried to avoid warning
        # about unknown channels.
        self.protocol.start()

        # Health check needs the protocol layer
        self.start_neighbours_healthcheck()

        self.start_event.set()

    def start_neighbours_healthcheck(self):
        for graph in self.token_to_channelgraph.values():
            for neighbour in graph.get_neighbours():
                if neighbour != ConnectionManager.BOOTSTRAP_ADDR:
                    self.start_health_check_for(neighbour)

    def stop(self):
        """ Stop the node. """
        # Needs to come before any greenlets joining
        self.stop_event.set()
        self.protocol.stop_and_wait()
        self.alarm.stop_async()

        wait_for = [self.alarm]
        wait_for.extend(self.protocol.greenlets)
        wait_for.extend(self.greenlet_task_dispatcher.stop())
        # We need a timeout to prevent an endless loop from trying to
        # contact the disconnected client
        gevent.wait(wait_for, timeout=self.shutdown_timeout)

        # Filters must be uninstalled after the alarm task has stopped. Since
        # the events are polled by an alarm task callback, if the filters are
        # uninstalled before the alarm task is fully stopped the callback
        # `poll_blockchain_events` will fail.
        #
        # We need a timeout to prevent an endless loop from trying to
        # contact the disconnected client
        try:
            with gevent.Timeout(self.shutdown_timeout):
                self.blockchain_events.uninstall_all_event_listeners()
        except (gevent.timeout.Timeout, RaidenShuttingDown):
            pass

        # save the state after all tasks are done
        if self.serialization_file:
            save_snapshot(self.serialization_file, self)

        if self.db_lock is not None:
            self.db_lock.release()

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.address))

    def restore_from_snapshots(self):
        data = load_snapshot(self.serialization_file)
        data_exists_and_is_recent = (
            data is not None and
            'registry_address' in data and
            data['registry_address'] == ROPSTEN_REGISTRY_ADDRESS
        )

        if data_exists_and_is_recent:
            first_channel = True
            for channel in data['channels']:
                try:
                    self.restore_channel(channel)
                    first_channel = False
                except AddressWithoutCode as e:
                    log.warn(
                        'Channel without code while restoring. Must have been '
                        'already settled while we were offline.',
                        error=str(e)
                    )
                except AttributeError as e:
                    if first_channel:
                        log.warn(
                            'AttributeError during channel restoring. If code has changed'
                            ' then this is fine. If not then please report a bug.',
                            error=str(e)
                        )
                        break
                    else:
                        raise

            for restored_queue in data['queues']:
                self.restore_queue(restored_queue)

            self.protocol.receivedhashes_to_acks = data['receivedhashes_to_acks']
            self.protocol.nodeaddresses_to_nonces = data['nodeaddresses_to_nonces']

            self.restore_transfer_states(data['transfers'])

    def set_block_number(self, block_number):
        state_change = Block(block_number)
        self.state_machine_event_handler.log_and_dispatch_to_all_tasks(state_change)

        for graph in self.token_to_channelgraph.values():
            for channel in graph.address_to_channel.values():
                channel.state_transition(state_change)

        # To avoid races, only update the internal cache after all the state
        # tasks have been updated.
        self._block_number = block_number

    def set_node_network_state(self, node_address, network_state):
        for graph in self.token_to_channelgraph.values():
            channel = graph.partneraddress_to_channel.get(node_address)

            if channel:
                channel.network_state = network_state

    def start_health_check_for(self, node_address):
        self.protocol.start_health_check(node_address)

    def get_block_number(self):
        return self._block_number

    def poll_blockchain_events(self, current_block=None):
        # pylint: disable=unused-argument
        on_statechange = self.state_machine_event_handler.on_blockchain_statechange

        for state_change in self.blockchain_events.poll_state_change(self._block_number):
            on_statechange(state_change)

    def find_channel_by_address(self, netting_channel_address_bin):
        for graph in self.token_to_channelgraph.values():
            channel = graph.address_to_channel.get(netting_channel_address_bin)

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

    def register_secret(self, secret: bytes):
        """ Register the secret with any channel that has a hashlock on it.

        This must search through all channels registered for a given hashlock
        and ignoring the tokens. Useful for refund transfer, split transfer,
        and token swaps.

        Raises:
            TypeError: If secret is unicode data.
        """
        if not isinstance(secret, bytes):
            raise TypeError('secret must be bytes')

        hashlock = sha3(secret)
        revealsecret_message = RevealSecret(secret)
        self.sign(revealsecret_message)

        for hash_channel in self.token_to_hashlock_to_channels.values():
            for channel in hash_channel[hashlock]:
                channel.register_secret(secret)

                # The protocol ignores duplicated messages.
                self.send_async(
                    channel.partner_state.address,
                    revealsecret_message,
                )

    def register_channel_for_hashlock(self, token_address, channel, hashlock):
        channels_registered = self.token_to_hashlock_to_channels[token_address][hashlock]

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
        channels_list = self.token_to_hashlock_to_channels[token_address][hashlock]
        channels_to_remove = list()

        revealsecret_message = RevealSecret(secret)
        self.sign(revealsecret_message)

        messages_to_send = []
        for channel in channels_list:
            # unlock a pending lock
            if channel.our_state.is_known(hashlock):
                secret = channel.create_secret(identifier, secret)
                self.sign(secret)

                channel.register_transfer(
                    self.get_block_number(),
                    secret,
                )

                messages_to_send.append((
                    channel.partner_state.address,
                    secret,
                ))

                channels_to_remove.append(channel)

            # withdraw a pending lock
            elif channel.partner_state.is_known(hashlock):
                if partner_secret_message:
                    is_balance_proof = (
                        partner_secret_message.sender == channel.partner_state.address and
                        partner_secret_message.channel == channel.channel_address
                    )

                    if is_balance_proof:
                        channel.register_transfer(
                            self.get_block_number(),
                            partner_secret_message,
                        )
                        channels_to_remove.append(channel)
                    else:
                        channel.register_secret(secret)
                        messages_to_send.append((
                            channel.partner_state.address,
                            revealsecret_message,
                        ))
                else:
                    channel.register_secret(secret)
                    messages_to_send.append((
                        channel.partner_state.address,
                        revealsecret_message,
                    ))

            else:
                log.error(
                    'Channel is registered for a given lock but the lock is not contained in it.'
                )

        for channel in channels_to_remove:
            channels_list.remove(channel)

        if not channels_list:
            del self.token_to_hashlock_to_channels[token_address][hashlock]

        # send the messages last to avoid races
        for recipient, message in messages_to_send:
            self.send_async(
                recipient,
                message,
            )

    def get_channel_details(self, token_address, netting_channel):
        channel_details = netting_channel.detail()
        our_state = ChannelEndState(
            channel_details['our_address'],
            channel_details['our_balance'],
            None,
            EMPTY_MERKLE_TREE,
        )
        partner_state = ChannelEndState(
            channel_details['partner_address'],
            channel_details['partner_balance'],
            None,
            EMPTY_MERKLE_TREE,
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

        # restoring balances from the blockchain since the serialized
        # value could be falling behind.
        channel_details = netting_channel.detail()

        # our_address is checked by detail
        assert channel_details['partner_address'] == serialized_channel.partner_address

        if serialized_channel.our_leaves:
            our_layers = compute_layers(serialized_channel.our_leaves)
            our_tree = MerkleTreeState(our_layers)
        else:
            our_tree = EMPTY_MERKLE_TREE

        our_state = ChannelEndState(
            channel_details['our_address'],
            channel_details['our_balance'],
            serialized_channel.our_balance_proof,
            our_tree,
        )

        if serialized_channel.partner_leaves:
            partner_layers = compute_layers(serialized_channel.partner_leaves)
            partner_tree = MerkleTreeState(partner_layers)
        else:
            partner_tree = EMPTY_MERKLE_TREE

        partner_state = ChannelEndState(
            channel_details['partner_address'],
            channel_details['partner_balance'],
            serialized_channel.partner_balance_proof,
            partner_tree,
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

        graph = self.token_to_channelgraph[token_address]
        graph.add_channel(details)
        channel = graph.address_to_channel.get(
            serialized_channel.channel_address,
        )

        channel.our_state.balance_proof = serialized_channel.our_balance_proof
        channel.partner_state.balance_proof = serialized_channel.partner_balance_proof

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
        self.blockchain_events.add_proxies_listeners(proxies)

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
            )

            self.manager_to_token[manager_address] = token_address
            self.token_to_channelgraph[token_address] = graph

            self.tokens_to_connectionmanagers[token_address] = ConnectionManager(
                self,
                token_address,
                graph
            )

    def channel_manager_is_registered(self, manager_address):
        return manager_address in self.manager_to_token

    def register_channel_manager(self, manager_address):
        manager = self.default_registry.manager(manager_address)
        netting_channels = [
            self.chain.netting_channel(channel_address)
            for channel_address in manager.channels_by_participant(self.address)
        ]

        # Install the filters first to avoid missing changes, as a consequence
        # some events might be applied twice.
        self.blockchain_events.add_channel_manager_listener(manager)
        for channel in netting_channels:
            self.blockchain_events.add_netting_channel_listener(channel)

        token_address = manager.token_address()
        edge_list = manager.channels_addresses()
        channels_detail = [
            self.get_channel_details(token_address, channel)
            for channel in netting_channels
        ]

        graph = ChannelGraph(
            self.address,
            manager_address,
            token_address,
            edge_list,
            channels_detail,
        )

        self.manager_to_token[manager_address] = token_address
        self.token_to_channelgraph[token_address] = graph

        self.tokens_to_connectionmanagers[token_address] = ConnectionManager(
            self,
            token_address,
            graph
        )

    def register_netting_channel(self, token_address, channel_address):
        netting_channel = self.chain.netting_channel(channel_address)
        self.blockchain_events.add_netting_channel_listener(netting_channel)

        detail = self.get_channel_details(token_address, netting_channel)
        graph = self.token_to_channelgraph[token_address]
        graph.add_channel(detail)

    def connection_manager_for_token(self, token_address):
        if not isaddress(token_address):
            raise InvalidAddress('token address is not valid.')
        if token_address in self.tokens_to_connectionmanagers.keys():
            manager = self.tokens_to_connectionmanagers[token_address]
        else:
            raise InvalidAddress('token is not registered.')
        return manager

    def leave_all_token_networks_async(self):
        leave_results = []
        for token_address in self.token_to_channelgraph.keys():
            try:
                connection_manager = self.connection_manager_for_token(token_address)
                leave_results.append(connection_manager.leave_async())
            except InvalidAddress:
                pass
        combined_result = AsyncResult()
        gevent.spawn(gevent.wait, leave_results).link(combined_result)
        return combined_result

    def close_and_settle(self):
        log.info('raiden will close and settle all channels now')

        connection_managers = [
            self.connection_manager_for_token(token_address) for
            token_address in self.token_to_channelgraph
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

    def mediated_transfer_async(self, token_address, amount, target, identifier):
        """ Transfer `amount` between this node and `target`.

        This method will start an asyncronous transfer, the transfer might fail
        or succeed depending on a couple of factors:

            - Existence of a path that can be used, through the usage of direct
              or intermediary channels.
            - Network speed, making the transfer sufficiently fast so it doesn't
              expire.
        """

        async_result = self.start_mediated_transfer(
            token_address,
            amount,
            identifier,
            target,
        )

        return async_result

    def direct_transfer_async(self, token_address, amount, target, identifier):
        """ Do a direct tranfer with target.

        Direct transfers are non cancellable and non expirable, since these
        transfers are a signed balance proof with the transferred amount
        incremented.

        Because the transfer is non cancellable, there is a level of trust with
        the target. After the message is sent the target is effectively paid
        and then it is not possible to revert.

        The async result will be set to False iff there is no direct channel
        with the target or the payer does not have balance to complete the
        transfer, otherwise because the transfer is non expirable the async
        result *will never be set to False* and if the message is sent it will
        hang until the target node acknowledge the message.

        This transfer should be used as an optimization, since only two packets
        are required to complete the transfer (from the payer's perspective),
        whereas the mediated transfer requires 6 messages.
        """
        graph = self.token_to_channelgraph[token_address]
        direct_channel = graph.partneraddress_to_channel.get(target)

        direct_channel_with_capacity = (
            direct_channel and
            direct_channel.can_transfer and
            amount <= direct_channel.distributable
        )

        if direct_channel_with_capacity:
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
                amount,
                target,
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

        else:
            async_result = AsyncResult()
            async_result.set(False)

        return async_result

    def start_mediated_transfer(self, token_address, amount, identifier, target):
        # pylint: disable=too-many-locals

        async_result = AsyncResult()
        graph = self.token_to_channelgraph[token_address]

        available_routes = get_best_routes(
            graph,
            self.protocol.nodeaddresses_networkstatuses,
            self.address,
            target,
            amount,
            None,
        )

        if not available_routes:
            async_result.set(False)
            return async_result

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
        graph = self.token_to_channelgraph[token]

        available_routes = get_best_routes(
            graph,
            self.protocol.nodeaddresses_networkstatuses,
            self.address,
            target,
            amount,
            message.sender,
        )

        from_channel = graph.partneraddress_to_channel[message.sender]
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
        graph = self.token_to_channelgraph[message.token]
        from_channel = graph.partneraddress_to_channel[message.sender]
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
