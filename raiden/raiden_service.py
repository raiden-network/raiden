# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines
import logging
import os
import random
import sys
from collections import defaultdict

import filelock
import gevent
from gevent.event import AsyncResult, Event
from coincurve import PrivateKey
from ethereum import slogging

from raiden import routing, waiting
from raiden.blockchain_events_handler import on_blockchain_event
from raiden.constants import (
    UINT64_MAX,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MIN,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MAX,
)
from raiden.blockchain.state import get_token_network_state_from_proxies
from raiden.blockchain.events import (
    get_relevant_proxies,
    BlockchainEvents,
)
from raiden.raiden_event_handler import on_raiden_event
from raiden.tasks import AlarmTask
from raiden.transfer import views, node
from raiden.transfer.state import (
    RouteState,
    PaymentNetworkState,
)
from raiden.transfer.mediated_transfer.state import (
    lockedtransfersigned_from_message,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.state_change import (
    ActionChangeNodeNetworkState,
    ActionInitNode,
    ActionLeaveAllNetworks,
    ActionTransferDirect,
    Block,
    ContractReceiveNewPaymentNetwork,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ActionInitTarget,
)
from raiden.exceptions import InvalidAddress, RaidenShuttingDown
from raiden.messages import SignedMessage
from raiden.network.protocol import RaidenProtocol
from raiden.connection_manager import ConnectionManager
from raiden.utils import (
    isaddress,
    pex,
    privatekey_to_address,
    random_secret,
)
from raiden.storage import wal, serialize, sqlite

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


def initiator_init(
        raiden,
        transfer_identifier,
        transfer_amount,
        transfer_secret,
        token_address,
        target_address):
    registry_address = raiden.default_registry.address
    transfer_state = TransferDescriptionWithSecretState(
        transfer_identifier,
        transfer_amount,
        registry_address,
        token_address,
        raiden.address,
        target_address,
        transfer_secret,
    )
    previous_address = None
    routes = routing.get_best_routes(
        views.state_from_raiden(raiden),
        registry_address,
        token_address,
        raiden.address,
        target_address,
        transfer_amount,
        previous_address,
    )
    init_initiator_statechange = ActionInitInitiator(
        registry_address,
        transfer_state,
        routes,
    )
    return init_initiator_statechange


def mediator_init(raiden, transfer):
    from_transfer = lockedtransfersigned_from_message(transfer)
    registry_address = raiden.default_registry.address
    routes = routing.get_best_routes(
        views.state_from_raiden(raiden),
        registry_address,
        from_transfer.token,
        raiden.address,
        from_transfer.target,
        from_transfer.lock.amount,
        transfer.sender,
    )
    from_route = RouteState(
        transfer.sender,
        from_transfer.balance_proof.channel_address,
    )
    init_mediator_statechange = ActionInitMediator(
        registry_address,
        routes,
        from_route,
        from_transfer,
    )
    return init_mediator_statechange


def target_init(raiden, transfer):
    from_transfer = lockedtransfersigned_from_message(transfer)
    from_route = RouteState(
        transfer.sender,
        from_transfer.balance_proof.channel_address,
    )
    registry_address = raiden.default_registry.address
    init_target_statechange = ActionInitTarget(
        registry_address,
        from_route,
        from_transfer,
    )
    return init_target_statechange


def create_default_identifier():
    """ Generates a random identifier. """
    return random.randint(0, UINT64_MAX)


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


class RaidenService:
    """ A Raiden node. """

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

        self.tokens_to_connectionmanagers = dict()
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

        self.blockchain_events = BlockchainEvents()
        self.alarm = AlarmTask(chain)
        self.shutdown_timeout = config['shutdown_timeout']
        self._block_number = None
        self.stop_event = Event()
        self.start_event = Event()
        self.chain.client.inject_stop_event(self.stop_event)

        self.wal = None

        self.database_path = config['database_path']
        if self.database_path != ':memory:':
            database_dir = os.path.dirname(config['database_path'])
            os.makedirs(database_dir, exist_ok=True)

            self.database_dir = database_dir
            # Prevent concurrent acces to the same db
            self.lock_file = os.path.join(self.database_dir, '.lock')
            self.db_lock = filelock.FileLock(self.lock_file)
        else:
            self.database_path = ':memory:'
            self.database_dir = None
            self.lock_file = None
            self.serialization_file = None
            self.db_lock = None

        # If the endpoint registration fails the node will quit, this must
        # finish before starting the protocol
        endpoint_registration_event.join()

        # Lock used to serialize calls to `poll_blockchain_events`, this is
        # important to give a consistent view of the node state.
        self.event_poll_lock = gevent.lock.Semaphore()

        self.start()

    def start(self):
        """ Start the node. """
        # XXX Should this really be here? Or will start() never be called again
        # after stop() in the lifetime of Raiden apart from the tests? This is
        # at least at the moment prompted by tests/integration/test_transer.py
        if self.stop_event and self.stop_event.is_set():
            self.stop_event.clear()

        if self.database_dir is not None:
            self.db_lock.acquire(timeout=0)
            assert self.db_lock.is_locked

        # The database may be :memory:
        storage = sqlite.SQLiteStorage(self.database_path, serialize.PickleSerializer())
        self.wal, unapplied_events = wal.restore_from_latest_snapshot(
            node.state_transition,
            storage,
        )

        # First run, initialize the basic state
        if self.wal.state_manager.current_state is None:
            block_number = self.chain.block_number()
            first_run = True

            state_change = ActionInitNode(block_number)
            self.wal.log_and_dispatch(state_change, block_number)

        # The alarm task must be started after the snapshot is loaded or the
        # state is primed, the callbacks assume the node is initialized.
        self.alarm.start()
        self.alarm.register_callback(self.poll_blockchain_events)
        self.alarm.register_callback(self.set_block_number)
        self._block_number = self.chain.block_number()

        # Registry registration must start *after* the alarm task. This
        # avoids corner cases where the registry is queried in block A, a new
        # block B is mined, and the alarm starts polling at block C.
        if first_run:
            self.register_payment_network(self.default_registry.address)

        # Start the protocol after the registry is queried to avoid warning
        # about unknown channels.
        self.protocol.start()

        # Health check needs the protocol layer
        self.start_neighbours_healthcheck()

        self.start_event.set()

        for event in unapplied_events:
            on_raiden_event(self, event)

    def start_neighbours_healthcheck(self):
        for neighbour in views.all_neighbour_nodes(self.wal.state_manager.current_state):
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

        if self.db_lock is not None:
            self.db_lock.release()

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.address))

    def set_block_number(self, block_number):
        state_change = Block(block_number)
        self.handle_state_change(state_change, block_number)

        # To avoid races, only update the internal cache after all the state
        # tasks have been updated.
        self._block_number = block_number

    def handle_state_change(self, state_change, block_number=None):
        is_logging = log.isEnabledFor(logging.DEBUG)

        if is_logging:
            log.debug('STATE CHANGE', node=pex(self.address), state_change=state_change)

        if block_number is None:
            block_number = self.get_block_number()

        event_list = self.wal.log_and_dispatch(state_change, block_number)

        for event in event_list:
            if is_logging:
                log.debug('EVENT', node=pex(self.address), event=event)

            on_raiden_event(self, event)

        return event_list

    def set_node_network_state(self, node_address, network_state):
        state_change = ActionChangeNodeNetworkState(node_address, network_state)
        self.wal.log_and_dispatch(state_change, self.get_block_number())

    def start_health_check_for(self, node_address):
        self.protocol.start_health_check(node_address)

    def get_block_number(self):
        return views.block_number(self.wal.state_manager.current_state)

    def poll_blockchain_events(self, current_block=None):  # pylint: disable=unused-argument
        with self.event_poll_lock:
            for event in self.blockchain_events.poll_blockchain_events():
                on_blockchain_event(self, event)

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

    def register_payment_network(self, registry_address):
        proxies = get_relevant_proxies(
            self.chain,
            self.address,
            registry_address,
        )

        # Install the filters first to avoid missing changes, as a consequence
        # some events might be applied twice.
        self.blockchain_events.add_proxies_listeners(proxies)

        token_network_list = list()
        for manager in proxies.channel_managers:
            manager_address = manager.address
            netting_channel_proxies = proxies.channelmanager_nettingchannels[manager_address]
            network = get_token_network_state_from_proxies(self, manager, netting_channel_proxies)
            token_network_list.append(network)

        payment_network = PaymentNetworkState(
            registry_address,
            token_network_list,
        )

        state_change = ContractReceiveNewPaymentNetwork(payment_network)
        self.handle_state_change(state_change)

    def connection_manager_for_token(self, token_address):
        if not isaddress(token_address):
            raise InvalidAddress('token address is not valid.')

        registry_address = self.default_registry.address
        known_token_networks = views.get_token_network_addresses_for(
            self.wal.state_manager.current_state,
            registry_address,
        )

        if token_address not in known_token_networks:
            raise InvalidAddress('token is not registered.')

        manager = self.tokens_to_connectionmanagers.get(token_address)

        if manager is None:
            manager = ConnectionManager(self, token_address)
            self.tokens_to_connectionmanagers[token_address] = manager

        return manager

    def leave_all_token_networks(self):
        state_change = ActionLeaveAllNetworks()
        self.wal.log_and_dispatch(state_change, self.get_block_number())

    def close_and_settle(self):
        log.info('raiden will close and settle all channels now')

        self.leave_all_token_networks()

        connection_managers = [
            self.tokens_to_connectionmanagers[token_address]
            for token_address in self.tokens_to_connectionmanagers
        ]

        if connection_managers:
            waiting.wait_for_settle_all_channels(
                self,
                self.alarm.wait_time,
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
        """ Do a direct transfer with target.

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
        are required to complete the transfer (from the payers perspective),
        whereas the mediated transfer requires 6 messages.
        """

        self.protocol.start_health_check(target)

        if identifier is None:
            identifier = create_default_identifier()

        registry_address = self.default_registry.address
        direct_transfer = ActionTransferDirect(
            registry_address,
            token_address,
            target,
            identifier,
            amount,
        )

        self.handle_state_change(direct_transfer)

    def start_mediated_transfer(self, token_address, amount, identifier, target):
        self.protocol.start_health_check(target)

        if identifier is None:
            identifier = create_default_identifier()

        assert identifier not in self.identifier_to_results

        async_result = AsyncResult()
        self.identifier_to_results[identifier].append(async_result)

        secret = random_secret()
        init_initiator_statechange = initiator_init(
            self,
            identifier,
            amount,
            secret,
            token_address,
            target,
        )

        # TODO: implement the network timeout raiden.config['msg_timeout'] and
        # cancel the current transfer if it happens (issue #374)
        #
        # Dispatch the state change even if there are no routes to create the
        # wal entry.
        self.handle_state_change(init_initiator_statechange)

        return async_result

    def mediate_mediated_transfer(self, transfer):
        init_mediator_statechange = mediator_init(self, transfer)
        self.handle_state_change(init_mediator_statechange)

    def target_mediated_transfer(self, transfer):
        init_target_statechange = target_init(self, transfer)
        self.handle_state_change(init_target_statechange)
