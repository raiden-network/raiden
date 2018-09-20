# pylint: disable=too-many-lines
import os
import random

import filelock
import gevent
import structlog
from coincurve import PrivateKey
from eth_utils import is_binary_address
from gevent.event import AsyncResult, Event
from gevent.lock import Semaphore

from raiden import constants, routing, waiting
from raiden.blockchain.events import BlockchainEvents
from raiden.blockchain_events_handler import on_blockchain_event
from raiden.connection_manager import ConnectionManager
from raiden.constants import SNAPSHOT_STATE_CHANGES_COUNT, NetworkType
from raiden.exceptions import (
    InvalidAddress,
    InvalidDBData,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
)
from raiden.messages import LockedTransfer, SignedMessage, message_from_sendevent
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies import SecretRegistry, TokenNetworkRegistry
from raiden.storage import serialize, sqlite, wal
from raiden.tasks import AlarmTask
from raiden.transfer import node, views
from raiden.transfer.events import SendDirectTransfer
from raiden.transfer.mediated_transfer.state import (
    TransferDescriptionWithSecretState,
    lockedtransfersigned_from_message,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ActionInitTarget,
)
from raiden.transfer.state import PaymentNetworkState, RouteState
from raiden.transfer.state_change import (
    ActionChangeNodeNetworkState,
    ActionInitChain,
    ActionLeaveAllNetworks,
    ActionTransferDirect,
    Block,
    ContractReceiveNewPaymentNetwork,
)
from raiden.utils import (
    create_default_identifier,
    lpex,
    pex,
    privatekey_to_address,
    random_secret,
    typing,
)
from raiden.utils.runnable import Runnable

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
        raiden.default_registry.address,
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
        from_transfer.balance_proof.channel_identifier,
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
        from_transfer.balance_proof.channel_identifier,
    )
    init_target_statechange = ActionInitTarget(
        from_route,
        from_transfer,
    )
    return init_target_statechange


class RaidenService(Runnable):
    """ A Raiden node. """

    def __init__(
            self,
            chain: BlockChainService,
            query_start_block: typing.BlockNumber,
            default_registry: TokenNetworkRegistry,
            default_secret_registry: SecretRegistry,
            private_key_bin,
            transport,
            raiden_event_handler,
            config,
            discovery=None,
    ):
        super().__init__()
        if not isinstance(private_key_bin, bytes) or len(private_key_bin) != 32:
            raise ValueError('invalid private_key')

        self.tokennetworkids_to_connectionmanagers = dict()
        self.identifier_to_results: typing.Dict[
            typing.PaymentID,
            AsyncResult,
        ] = dict()

        self.chain: BlockChainService = chain
        self.default_registry = default_registry
        self.query_start_block = query_start_block
        self.default_secret_registry = default_secret_registry
        self.config = config
        self.privkey = private_key_bin
        self.address = privatekey_to_address(private_key_bin)
        self.discovery = discovery

        self.private_key = PrivateKey(private_key_bin)
        self.pubkey = self.private_key.public_key.format(compressed=False)
        self.transport = transport

        self.blockchain_events = BlockchainEvents()
        self.alarm = AlarmTask(chain)
        self.raiden_event_handler = raiden_event_handler

        self.stop_event = Event()
        self.stop_event.set()  # inits as stopped

        self.wal = None
        self.snapshot_group = 0

        # This flag will be used to prevent the service from processing
        # state changes events until we know that pending transactions
        # have been dispatched.
        self.dispatch_events_lock = Semaphore(1)

        self.database_path = config['database_path']
        if self.database_path != ':memory:':
            database_dir = os.path.dirname(config['database_path'])
            os.makedirs(database_dir, exist_ok=True)

            self.database_dir = database_dir
            # Prevent concurrent access to the same db
            self.lock_file = os.path.join(self.database_dir, '.lock')
            self.db_lock = filelock.FileLock(self.lock_file)
        else:
            self.database_path = ':memory:'
            self.database_dir = None
            self.lock_file = None
            self.serialization_file = None
            self.db_lock = None

        self.event_poll_lock = gevent.lock.Semaphore()

    def start(self):
        """ Start the node synchronously. Raises directly if anything went wrong on startup """
        if not self.stop_event.ready():
            raise RuntimeError(f'{self!r} already started')
        self.stop_event.clear()

        if self.database_dir is not None:
            self.db_lock.acquire(timeout=0)
            assert self.db_lock.is_locked

        # start the registration early to speed up the start
        if self.config['transport_type'] == 'udp':
            endpoint_registration_greenlet = gevent.spawn(
                self.discovery.register,
                self.address,
                self.config['transport']['udp']['external_ip'],
                self.config['transport']['udp']['external_port'],
            )

        storage = sqlite.SQLiteStorage(self.database_path, serialize.JSONSerializer())
        self.wal = wal.restore_to_state_change(
            transition_function=node.state_transition,
            storage=storage,
            state_change_identifier='latest',
        )

        if self.wal.state_manager.current_state is None:
            log.debug(
                'No recoverable state available, created inital state',
                node=pex(self.address),
            )
            block_number = self.chain.block_number()

            state_change = ActionInitChain(
                random.Random(),
                block_number,
                self.chain.node_address,
                self.chain.network_id,
            )
            self.wal.log_and_dispatch(state_change)
            payment_network = PaymentNetworkState(
                self.default_registry.address,
                [],  # empty list of token network states as it's the node's startup
            )
            state_change = ContractReceiveNewPaymentNetwork(
                constants.EMPTY_HASH,
                payment_network,
            )
            self.handle_state_change(state_change)

            # On first run Raiden needs to fetch all events for the payment
            # network, to reconstruct all token network graphs and find opened
            # channels
            last_log_block_number = 0
        else:
            # The `Block` state change is dispatched only after all the events
            # for that given block have been processed, filters can be safely
            # installed starting from this position without losing events.
            last_log_block_number = views.block_number(self.wal.state_manager.current_state)
            log.debug(
                'Restored state from WAL',
                last_restored_block=last_log_block_number,
                node=pex(self.address),
            )

            known_networks = views.get_payment_network_identifiers(views.state_from_raiden(self))
            if known_networks and self.default_registry.address not in known_networks:
                configured_registry = pex(self.default_registry.address)
                known_registries = lpex(known_networks)
                raise RuntimeError(
                    f'Token network address mismatch.\n'
                    f'Raiden is configured to use the smart contract '
                    f'{configured_registry}, which conflicts with the current known '
                    f'smart contracts {known_registries}',
                )

        # Clear ref cache & disable caching
        serialize.RaidenJSONDecoder.ref_cache.clear()
        serialize.RaidenJSONDecoder.cache_object_references = False

        # Restore the current snapshot group
        state_change_qty = self.wal.storage.count_state_changes()
        self.snapshot_group = state_change_qty // SNAPSHOT_STATE_CHANGES_COUNT

        # Install the filters using the correct from_block value, otherwise
        # blockchain logs can be lost.
        self.install_all_blockchain_filters(
            self.default_registry,
            self.default_secret_registry,
            last_log_block_number,
        )

        # Complete the first_run of the alarm task and synchronize with the
        # blockchain since the last run.
        #
        # Notes about setup order:
        # - The filters must be polled after the node state has been primed,
        # otherwise the state changes won't have effect.
        # - The alarm must complete its first run  before the transport is started,
        #  to avoid rejecting messages for unknown channels.
        self.alarm.register_callback(self._callback_new_block)

        # alarm.first_run may process some new channel, which would start_health_check_for
        # a partner, that's why transport needs to be already started at this point
        self.transport.start(self)

        self.alarm.first_run()

        chain_state = views.state_from_raiden(self)
        # Dispatch pending transactions
        pending_transactions = views.get_pending_transactions(
            chain_state,
        )
        log.debug(
            'Processing pending transactions',
            num_pending_transactions=len(pending_transactions),
            node=pex(self.address),
        )
        with self.dispatch_events_lock:
            for transaction in pending_transactions:
                try:
                    self.raiden_event_handler.on_raiden_event(self, transaction)
                except RaidenRecoverableError as e:
                    log.error(str(e))
                except RaidenUnrecoverableError as e:
                    if self.config['network_type'] == NetworkType.MAIN:
                        if isinstance(e, InvalidDBData):
                            raise
                        log.error(str(e))
                    else:
                        raise

        self.alarm.start()

        # after transport and alarm is started, send queued messages
        events_queues = views.get_all_messagequeues(chain_state)

        for queue_identifier, event_queue in events_queues.items():
            self.start_health_check_for(queue_identifier.recipient)

            # repopulate identifier_to_results for pending transfers
            for event in event_queue:
                if type(event) == SendDirectTransfer:
                    self.identifier_to_results[event.payment_identifier] = AsyncResult()

                message = message_from_sendevent(event, self.address)
                self.sign(message)
                self.transport.send_async(queue_identifier, message)

        # exceptions on these subtasks should crash the app and bubble up
        self.alarm.link_exception(self.on_error)
        self.transport.link_exception(self.on_error)

        # Health check needs the transport layer
        self.start_neighbours_healthcheck()

        if self.config['transport_type'] == 'udp':
            endpoint_registration_greenlet.get()  # re-raise if exception occurred

        super().start()

    def _run(self):
        """ Busy-wait on long-lived subtasks/greenlets, re-raise if any error occurs """
        try:
            self.stop_event.wait()
        except gevent.GreenletExit:  # killed without exception
            self.stop_event.set()
            gevent.killall([self.alarm, self.transport])  # kill children
            raise  # re-raise to keep killed status
        except Exception:
            self.stop()
            raise

    def stop(self):
        """ Stop the node gracefully. Raise if any stop-time error occurred on any subtask """
        if self.stop_event.ready():  # not started
            return

        # Needs to come before any greenlets joining
        self.stop_event.set()

        # Filters must be uninstalled after the alarm task has stopped. Since
        # the events are polled by an alarm task callback, if the filters are
        # uninstalled before the alarm task is fully stopped the callback
        # `poll_blockchain_events` will fail.
        #
        # We need a timeout to prevent an endless loop from trying to
        # contact the disconnected client
        try:
            self.transport.stop()
            self.alarm.stop()
            self.transport.get()
            self.alarm.get()
            self.blockchain_events.uninstall_all_event_listeners()
        except gevent.Timeout:
            pass

        self.blockchain_events.reset()

        if self.db_lock is not None:
            self.db_lock.release()

    def add_pending_greenlet(self, greenlet: gevent.Greenlet):
        greenlet.link_exception(self.on_error)

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.address))

    def start_neighbours_healthcheck(self):
        for neighbour in views.all_neighbour_nodes(self.wal.state_manager.current_state):
            if neighbour != ConnectionManager.BOOTSTRAP_ADDR:
                self.start_health_check_for(neighbour)

    def get_block_number(self):
        return views.block_number(self.wal.state_manager.current_state)

    def handle_state_change(self, state_change):
        log.debug('STATE CHANGE', node=pex(self.address), state_change=state_change)

        event_list = self.wal.log_and_dispatch(state_change)

        if self.dispatch_events_lock.locked():
            return []

        for event in event_list:
            log.debug('RAIDEN EVENT', node=pex(self.address), raiden_event=event)

            try:
                self.raiden_event_handler.on_raiden_event(
                    raiden=self,
                    event=event,
                )
            except RaidenRecoverableError as e:
                log.error(str(e))
            except RaidenUnrecoverableError as e:
                if self.config['network_type'] == NetworkType.MAIN:
                    if isinstance(e, InvalidDBData):
                        raise
                    log.error(str(e))
                else:
                    raise

        # Take a snapshot every SNAPSHOT_STATE_CHANGES_COUNT
        # TODO: Gather more data about storage requirements
        # and update the value to specify how often we need
        # capturing a snapshot should take place
        new_snapshot_group = self.wal.storage.count_state_changes() // SNAPSHOT_STATE_CHANGES_COUNT
        if new_snapshot_group > self.snapshot_group:
            log.debug(f'Storing snapshot: {new_snapshot_group}')
            self.wal.snapshot()
            self.snapshot_group = new_snapshot_group

        return event_list

    def set_node_network_state(self, node_address, network_state):
        state_change = ActionChangeNodeNetworkState(node_address, network_state)
        self.wal.log_and_dispatch(state_change)

    def start_health_check_for(self, node_address):
        self.transport.start_health_check(node_address)

    def _callback_new_block(self, latest_block):
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
        latest_block_number = latest_block['number']
        with self.event_poll_lock:
            for event in self.blockchain_events.poll_blockchain_events(latest_block_number):
                # These state changes will be procesed with a block_number
                # which is /larger/ than the ChainState's block_number.
                on_blockchain_event(self, event)

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
            state_change = Block(
                block_number=latest_block_number,
                gas_limit=latest_block['gasLimit'],
                block_hash=bytes(latest_block['hash']),
            )
            self.handle_state_change(state_change)

    def sign(self, message):
        """ Sign message inplace. """
        if not isinstance(message, SignedMessage):
            raise ValueError('{} is not signable.'.format(repr(message)))

        message.sign(self.private_key)

    def install_all_blockchain_filters(
            self,
            token_network_registry_proxy: TokenNetworkRegistry,
            secret_registry_proxy: SecretRegistry,
            from_block: typing.BlockNumber,
    ):
        with self.event_poll_lock:
            node_state = views.state_from_raiden(self)
            token_networks = views.get_token_network_identifiers(
                node_state,
                token_network_registry_proxy.address,
            )

            self.blockchain_events.add_token_network_registry_listener(
                token_network_registry_proxy,
                from_block,
            )
            self.blockchain_events.add_secret_registry_listener(
                secret_registry_proxy,
                from_block,
            )

            for token_network in token_networks:
                token_network_proxy = self.chain.token_network(token_network)
                self.blockchain_events.add_token_network_listener(
                    token_network_proxy,
                    from_block,
                )

    def connection_manager_for_token_network(self, token_network_identifier):
        if not is_binary_address(token_network_identifier):
            raise InvalidAddress('token address is not valid.')

        known_token_networks = views.get_token_network_identifiers(
            views.state_from_raiden(self),
            self.default_registry.address,
        )

        if token_network_identifier not in known_token_networks:
            raise InvalidAddress('token is not registered.')

        manager = self.tokennetworkids_to_connectionmanagers.get(token_network_identifier)

        if manager is None:
            manager = ConnectionManager(self, token_network_identifier)
            self.tokennetworkids_to_connectionmanagers[token_network_identifier] = manager

        return manager

    def leave_all_token_networks(self):
        state_change = ActionLeaveAllNetworks()
        self.wal.log_and_dispatch(state_change)

    def close_and_settle(self):
        log.info('raiden will close and settle all channels now')

        self.leave_all_token_networks()

        connection_managers = [cm for cm in self.tokennetworkids_to_connectionmanagers.values()]

        if connection_managers:
            waiting.wait_for_settle_all_channels(
                self,
                self.alarm.sleep_time,
            )

    def mediated_transfer_async(
            self,
            token_network_identifier: typing.TokenNetworkID,
            amount: typing.TokenAmount,
            target: typing.Address,
            identifier: typing.PaymentID,
    ):
        """ Transfer `amount` between this node and `target`.

        This method will start an asynchronous transfer, the transfer might fail
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

        self.start_health_check_for(target)

        if identifier is None:
            identifier = create_default_identifier()

        direct_transfer = ActionTransferDirect(
            token_network_identifier,
            target,
            identifier,
            amount,
        )

        async_result = AsyncResult()
        self.identifier_to_results[identifier] = async_result

        self.handle_state_change(direct_transfer)

    def start_mediated_transfer(
            self,
            token_network_identifier: typing.TokenNetworkID,
            amount: typing.TokenAmount,
            target: typing.Address,
            identifier: typing.PaymentID,
    ):

        self.start_health_check_for(target)

        if identifier is None:
            identifier = create_default_identifier()

        if identifier in self.identifier_to_results:
            return self.identifier_to_results[identifier]

        async_result = AsyncResult()
        self.identifier_to_results[identifier] = async_result

        secret = random_secret()
        init_initiator_statechange = initiator_init(
            self,
            identifier,
            amount,
            secret,
            token_network_identifier,
            target,
        )

        # Dispatch the state change even if there are no routes to create the
        # wal entry.
        self.handle_state_change(init_initiator_statechange)

        return async_result

    def mediate_mediated_transfer(self, transfer: LockedTransfer):
        init_mediator_statechange = mediator_init(self, transfer)
        self.handle_state_change(init_mediator_statechange)

    def target_mediated_transfer(self, transfer: LockedTransfer):
        self.start_health_check_for(transfer.initiator)
        init_target_statechange = target_init(transfer)
        self.handle_state_change(init_target_statechange)
