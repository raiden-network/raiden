# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines
import os
import random
import sys
from collections import defaultdict

import filelock
import gevent
from gevent.event import AsyncResult, Event
from coincurve import PrivateKey
import structlog
from eth_utils import is_binary_address

from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies import (
    Registry,
    SecretRegistry,
)
from raiden import routing, waiting
from raiden.blockchain_events_handler import on_blockchain_event
from raiden.constants import (
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
from raiden.messages import (LockedTransfer, SignedMessage)
from raiden.connection_manager import ConnectionManager
from raiden.utils import (
    pex,
    privatekey_to_address,
    random_secret,
    create_default_identifier,
)
from raiden.storage import wal, serialize, sqlite

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def initiator_init(
        raiden,
        transfer_identifier,
        transfer_amount,
        transfer_secret,
        token_network_identifier,
        target_address,
):

    transfer_state = TransferDescriptionWithSecretState(
        transfer_identifier,
        transfer_amount,
        token_network_identifier,
        raiden.address,
        target_address,
        transfer_secret,
    )
    previous_address = None
    routes = routing.get_best_routes(
        views.state_from_raiden(raiden),
        token_network_identifier,
        raiden.address,
        target_address,
        transfer_amount,
        previous_address,
    )
    init_initiator_statechange = ActionInitInitiator(
        transfer_state,
        routes,
    )
    return init_initiator_statechange


def mediator_init(raiden, transfer: LockedTransfer):
    from_transfer = lockedtransfersigned_from_message(transfer)
    routes = routing.get_best_routes(
        views.state_from_raiden(raiden),
        from_transfer.balance_proof.token_network_identifier,
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
        routes,
        from_route,
        from_transfer,
    )
    return init_mediator_statechange


def target_init(transfer: LockedTransfer):
    from_transfer = lockedtransfersigned_from_message(transfer)
    from_route = RouteState(
        transfer.sender,
        from_transfer.balance_proof.channel_address,
    )
    init_target_statechange = ActionInitTarget(
        from_route,
        from_transfer,
    )
    return init_target_statechange


def endpoint_registry_exception_handler(greenlet):
    try:
        greenlet.get()
    except Exception as e:  # pylint: disable=broad-except
        rpc_unreachable = (
            e.args[0] == 'timeout when polling for transaction'
        )

        if rpc_unreachable:
            log.exception('Endpoint registry failed. Ethereum RPC API might be unreachable.')
        else:
            log.exception('Endpoint registry failed.')

        sys.exit(1)


class RaidenService:
    """ A Raiden node. """

    def __init__(
            self,
            chain: BlockChainService,
            default_registry: Registry,
            default_secret_registry: SecretRegistry,
            private_key_bin,
            transport,
            config,
            discovery=None,
    ):
        if not isinstance(private_key_bin, bytes) or len(private_key_bin) != 32:
            raise ValueError('invalid private_key')

        invalid_timeout = (
            config['settle_timeout'] < NETTINGCHANNEL_SETTLE_TIMEOUT_MIN or
            config['settle_timeout'] > NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
        )
        if invalid_timeout:
            raise ValueError('settle_timeout must be in range [{}, {}]'.format(
                NETTINGCHANNEL_SETTLE_TIMEOUT_MIN, NETTINGCHANNEL_SETTLE_TIMEOUT_MAX,
            ))

        self.tokens_to_connectionmanagers = dict()
        self.identifier_to_results = defaultdict(list)

        self.chain: BlockChainService = chain
        self.default_registry = default_registry
        self.default_secret_registry = default_secret_registry
        self.config = config
        self.privkey = private_key_bin
        self.address = privatekey_to_address(private_key_bin)

        if config['transport_type'] == 'udp':
            endpoint_registration_event = gevent.spawn(
                discovery.register,
                self.address,
                config['external_ip'],
                config['external_port'],
            )
            endpoint_registration_event.link_exception(endpoint_registry_exception_handler)

        self.private_key = PrivateKey(private_key_bin)
        self.pubkey = self.private_key.public_key.format(compressed=False)
        self.transport = transport

        self.blockchain_events = BlockchainEvents()
        self.alarm = AlarmTask(chain)
        self.shutdown_timeout = config['shutdown_timeout']
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

        if config['transport_type'] == 'udp':
            # If the endpoint registration fails the node will quit, this must
            # finish before starting the transport
            endpoint_registration_event.join()

        self.event_poll_lock = gevent.lock.Semaphore()

        self.start()

    def start(self):
        """ Start the node. """
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

        if self.wal.state_manager.current_state is None:
            block_number = self.chain.block_number()

            state_change = ActionInitNode(
                random.Random(),
                block_number,
            )
            self.wal.log_and_dispatch(state_change, block_number)

            # On first run Raiden needs to fetch all events for the payment
            # network, to reconstruct all token network graphs and find opened
            # channels
            last_log_block_number = None
        else:
            # The `Block` state change is dispatched only after all the events
            # for that given block have been processed, filters can be safely
            # installed starting from this position without losing events.
            last_log_block_number = views.block_number(self.wal.state_manager.current_state)

        # The time the alarm task is started or the callbacks are installed doesn't
        # really matter.
        #
        # But it is of paramount importance to:
        # - Install the filters which will be polled by poll_blockchain_events
        #   after the state has been primed, otherwise the state changes won't
        #   have effect.
        # - Install the filters using the correct from_block value, otherwise
        #   blockchain logs can be lost.
        self.alarm.register_callback(self._callback_new_block)
        self.alarm.start()

        self.install_payment_network_filters(
            self.default_registry.address,
            last_log_block_number,
        )

        # Start the transport after the registry is queried to avoid warning
        # about unknown channels.
        queueids_to_queues = views.get_all_messagequeues(views.state_from_raiden(self))
        self.transport.start(self, queueids_to_queues)

        # Health check needs the transport layer
        self.start_neighbours_healthcheck()

        for event in unapplied_events:
            on_raiden_event(self, event)

        self.start_event.set()

    def start_neighbours_healthcheck(self):
        for neighbour in views.all_neighbour_nodes(self.wal.state_manager.current_state):
            if neighbour != ConnectionManager.BOOTSTRAP_ADDR:
                self.start_health_check_for(neighbour)

    def stop(self):
        """ Stop the node. """
        # Needs to come before any greenlets joining
        self.stop_event.set()
        self.transport.stop_and_wait()
        self.alarm.stop_async()

        wait_for = [self.alarm]
        wait_for.extend(getattr(self.transport, 'greenlets', []))
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

    def get_block_number(self):
        return views.block_number(self.wal.state_manager.current_state)

    def handle_state_change(self, state_change, block_number=None):
        log.debug('STATE CHANGE', node=pex(self.address), state_change=state_change)

        if block_number is None:
            block_number = self.get_block_number()

        event_list = self.wal.log_and_dispatch(state_change, block_number)

        for event in event_list:
            log.debug('EVENT', node=pex(self.address), chain_event=event)

            on_raiden_event(self, event)

        return event_list

    def set_node_network_state(self, node_address, network_state):
        state_change = ActionChangeNodeNetworkState(node_address, network_state)
        self.wal.log_and_dispatch(state_change, self.get_block_number())

    def start_health_check_for(self, node_address):
        self.transport.start_health_check(node_address)

    def _callback_new_block(self, current_block_number):
        """Called once a new block is detected by the alarm task.

        Note:
            This should be called only once per block, otherwise there will be
            duplicated `Block` state changes in the log.

            Therefore this method should be called only once a new block is
            mined with the appropriate block_number argument from the
            AlarmTask.
        """
        # Raiden relies on blockchain events to update its off-chain state,
        # therefore some APIs /used/ to forcefully poll for events.
        #
        # This was done for APIs which have on-chain side-effects, e.g.
        # openning a channel, where polling the event is required to update
        # off-chain state to providing a consistent view to the caller, e.g.
        # the channel exists after the API call returns.
        #
        # That pattern introduced a race, because the events are returned only
        # once per filter, and this method would be called concurrently by the
        # API and the AlarmTask. The following lock is necessary, to ensure the
        # expected side-effects are properly applied (introduced by the commit
        # 3686b3275ff7c0b669a6d5e2b34109c3bdf1921d)
        with self.event_poll_lock:
            for event in self.blockchain_events.poll_blockchain_events():
                # These state changes will be procesed with a block_number
                # which is /larger/ than the NodeState's block_number.
                on_blockchain_event(self, event, current_block_number)

            # On restart the Raiden node will re-create the filters with the
            # ethereum node. These filters will have the from_block set to the
            # value of the latest Block state change. To avoid missing events
            # the Block state change is dispatched only after all of the events
            # have been processed.
            #
            # This means on some corner cases a few events may be applied
            # twice, this will happen if the node crashed and some events have
            # been processed but the Block state change has not been
            # dispatched.
            state_change = Block(current_block_number)
            self.handle_state_change(state_change, current_block_number)

    def sign(self, message):
        """ Sign message inplace. """
        if not isinstance(message, SignedMessage):
            raise ValueError('{} is not signable.'.format(repr(message)))

        message.sign(self.private_key)

    def install_payment_network_filters(self, payment_network_id, from_block=None):
        proxies = get_relevant_proxies(
            self.chain,
            self.address,
            payment_network_id,
        )

        # Install the filters first to avoid missing changes, as a consequence
        # some events might be applied twice.
        self.blockchain_events.add_proxies_listeners(proxies, from_block)

        token_network_list = list()
        for manager in proxies.channel_managers:
            manager_address = manager.address
            netting_channel_proxies = proxies.channelmanager_nettingchannels[manager_address]
            network = get_token_network_state_from_proxies(self, manager, netting_channel_proxies)
            token_network_list.append(network)

        payment_network = PaymentNetworkState(
            payment_network_id,
            token_network_list,
        )

        state_change = ContractReceiveNewPaymentNetwork(payment_network)
        self.handle_state_change(state_change)

    def connection_manager_for_token(self, registry_address, token_address):
        if not is_binary_address(token_address):
            raise InvalidAddress('token address is not valid.')

        known_token_networks = views.get_token_network_addresses_for(
            self.wal.state_manager.current_state,
            registry_address,
        )

        if token_address not in known_token_networks:
            raise InvalidAddress('token is not registered.')

        manager = self.tokens_to_connectionmanagers.get(token_address)

        if manager is None:
            manager = ConnectionManager(self, registry_address, token_address)
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

    def mediated_transfer_async(
            self,
            token_network_identifier,
            amount,
            target,
            identifier,
    ):
        """ Transfer `amount` between this node and `target`.

        This method will start an asyncronous transfer, the transfer might fail
        or succeed depending on a couple of factors:

            - Existence of a path that can be used, through the usage of direct
              or intermediary channels.
            - Network speed, making the transfer sufficiently fast so it doesn't
              expire.
        """

        async_result = self.start_mediated_transfer(
            token_network_identifier,
            amount,
            target,
            identifier,
        )

        return async_result

    def direct_transfer_async(self, token_network_identifier, amount, target, identifier):
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

        self.transport.start_health_check(target)

        if identifier is None:
            identifier = create_default_identifier()

        direct_transfer = ActionTransferDirect(
            token_network_identifier,
            target,
            identifier,
            amount,
        )

        self.handle_state_change(direct_transfer)

    def start_mediated_transfer(
            self,
            token_network_identifier,
            amount,
            target,
            identifier,
    ):

        self.transport.start_health_check(target)

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
            token_network_identifier,
            target,
        )

        # TODO: implement the network timeout raiden.config['msg_timeout'] and
        # cancel the current transfer if it happens (issue #374)
        #
        # Dispatch the state change even if there are no routes to create the
        # wal entry.
        self.handle_state_change(init_initiator_statechange)

        return async_result

    def mediate_mediated_transfer(self, transfer: LockedTransfer):
        init_mediator_statechange = mediator_init(self, transfer)
        self.handle_state_change(init_mediator_statechange)

    def target_mediated_transfer(self, transfer: LockedTransfer):
        init_target_statechange = target_init(transfer)
        self.handle_state_change(init_target_statechange)
