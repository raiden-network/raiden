# pylint: disable=too-many-lines
import enum
import os
import random
from collections import defaultdict

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
from raiden.constants import GENESIS_BLOCK_NUMBER, SNAPSHOT_STATE_CHANGES_COUNT, Environment
from raiden.exceptions import (
    InvalidAddress,
    InvalidDBData,
    PaymentConflict,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
)
from raiden.messages import LockedTransfer, Message, SignedMessage, message_from_sendevent
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies import SecretRegistry, TokenNetworkRegistry
from raiden.storage import serialize, sqlite, wal
from raiden.tasks import AlarmTask
from raiden.transfer import node, views
from raiden.transfer.events import SendDirectTransfer
from raiden.transfer.mediated_transfer.events import SendLockedTransfer
from raiden.transfer.mediated_transfer.state import (
    TransferDescriptionWithSecretState,
    lockedtransfersigned_from_message,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ActionInitTarget,
)
from raiden.transfer.state import BalanceProofUnsignedState, PaymentNetworkState, RouteState
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
    sha3,
    typing,
)
from raiden.utils.runnable import Runnable
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def _redact_secret(data):
    """ Modify `data` in-place and replace keys named `secret`. """

    if isinstance(data, dict):
        stack = [data]
    else:
        stack = []

    while stack:
        current = stack.pop()

        if 'secret' in current:
            current['secret'] = '<redacted>'
        else:
            stack.extend(
                value
                for value in current.values()
                if isinstance(value, dict)
            )

    return data


def initiator_init(
        raiden: 'RaidenService',
        transfer_identifier: typing.PaymentID,
        transfer_amount: typing.PaymentAmount,
        transfer_secret: typing.Secret,
        token_network_identifier: typing.TokenNetworkID,
        target_address: typing.TargetAddress,
):

    msg = 'Should never end up initiating transfer with Secret 0x0'
    assert transfer_secret != constants.EMPTY_HASH, msg
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


class PaymentType(enum.Enum):
    DIRECT = 1
    MEDIATED = 2


class PaymentStatus(typing.NamedTuple):
    """Value type for RaidenService.targets_to_identifiers_to_statuses.

    Contains the necessary information to tell conflicting transfers from
    retries as well as the status of a transfer that is retried.
    """
    payment_type: PaymentType
    payment_identifier: typing.PaymentID
    amount: typing.TokenAmount
    token_network_identifier: typing.TokenNetworkID
    payment_done: AsyncResult

    def matches(
            self,
            payment_type: PaymentType,
            token_network_identifier: typing.TokenNetworkID,
            amount: typing.TokenAmount,
    ):
        return (
            payment_type == self.payment_type and
            token_network_identifier == self.token_network_identifier and
            amount == self.amount
        )


StatusesDict = typing.Dict[typing.TargetAddress, typing.Dict[typing.PaymentID, PaymentStatus]]


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
            message_handler,
            config,
            discovery=None,
    ):
        super().__init__()
        if not isinstance(private_key_bin, bytes) or len(private_key_bin) != 32:
            raise ValueError('invalid private_key')

        self.tokennetworkids_to_connectionmanagers = dict()
        self.targets_to_identifiers_to_statuses: StatusesDict = defaultdict(dict)

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
        self.message_handler = message_handler

        self.stop_event = Event()
        self.stop_event.set()  # inits as stopped

        self.wal = None
        self.snapshot_group = 0

        # This flag will be used to prevent the service from processing
        # state changes events until we know that pending transactions
        # have been dispatched.
        self.dispatch_events_lock = Semaphore(1)

        self.contract_manager = ContractManager(config['contracts_path'])
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
        self.gas_reserve_lock = gevent.lock.Semaphore()

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
            # On first run Raiden needs to fetch all events for the payment
            # network, to reconstruct all token network graphs and find opened
            # channels
            last_log_block_number = self.query_start_block

            state_change = ActionInitChain(
                random.Random(),
                last_log_block_number,
                self.chain.node_address,
                self.chain.network_id,
            )
            self.handle_state_change(state_change)

            payment_network = PaymentNetworkState(
                self.default_registry.address,
                [],  # empty list of token network states as it's the node's startup
            )
            state_change = ContractReceiveNewPaymentNetwork(
                constants.EMPTY_HASH,
                payment_network,
                last_log_block_number,
            )
            self.handle_state_change(state_change)
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
        # - The alarm must complete its first run before the transport is started,
        #   to reject messages for closed/settled channels.
        self.alarm.register_callback(self._callback_new_block)
        self.alarm.first_run(last_log_block_number)

        chain_state = views.state_from_raiden(self)

        self._initialize_transactions_queues(chain_state)
        self._initialize_whitelists(chain_state)

        # send messages in queue before starting transport,
        # this is necessary to avoid a race where, if the transport is started
        # before the messages are queued, actions triggered by it can cause new
        # messages to be enqueued before these older ones
        self._initialize_messages_queues(chain_state)

        # The transport must not ever be started before the alarm task's
        # `first_run()` has been, because it's this method which synchronizes the
        # node with the blockchain, including the channel's state (if the channel
        # is closed on-chain new messages must be rejected, which will not be the
        # case if the node is not synchronized)
        self.transport.start(
            raiden_service=self,
            message_handler=self.message_handler,
            fetch_since_token=chain_state.last_transport_synctoken,
        )

        # First run has been called above!
        self.alarm.start()

        # exceptions on these subtasks should crash the app and bubble up
        self.alarm.link_exception(self.on_error)
        self.transport.link_exception(self.on_error)

        # Health check needs the transport layer
        self.start_neighbours_healthcheck(chain_state)

        if self.config['transport_type'] == 'udp':
            endpoint_registration_greenlet.get()  # re-raise if exception occurred

        log.debug('Raiden Service started', node=pex(self.address))
        super().start()

    def _run(self, *args, **kwargs):  # pylint: disable=method-hidden
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
        self.transport.stop()
        self.alarm.stop()

        self.transport.join()
        self.alarm.join()

        self.blockchain_events.uninstall_all_event_listeners()

        if self.db_lock is not None:
            self.db_lock.release()

        log.debug('Raiden Service stopped', node=pex(self.address))

    def add_pending_greenlet(self, greenlet: gevent.Greenlet):
        greenlet.link_exception(self.on_error)

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.address))

    def start_neighbours_healthcheck(self, chain_state):
        for neighbour in views.all_neighbour_nodes(chain_state):
            if neighbour != ConnectionManager.BOOTSTRAP_ADDR:
                self.start_health_check_for(neighbour)

    def get_block_number(self):
        return views.block_number(self.wal.state_manager.current_state)

    def on_message(self, message: Message):
        self.message_handler.on_message(self, message)

    def handle_state_change(self, state_change):
        log.debug(
            'State change',
            node=pex(self.address),
            state_change=_redact_secret(serialize.JSONSerializer.serialize(state_change)),
        )

        event_list = self.wal.log_and_dispatch(state_change)

        if self.dispatch_events_lock.locked():
            return []

        for event in event_list:
            log.debug(
                'Raiden event',
                node=pex(self.address),
                raiden_event=_redact_secret(serialize.JSONSerializer.serialize(event)),
            )

            try:
                self.raiden_event_handler.on_raiden_event(
                    raiden=self,
                    event=event,
                )
            except RaidenRecoverableError as e:
                log.error(str(e))
            except InvalidDBData:
                raise
            except RaidenUnrecoverableError as e:
                log_unrecoverable = (
                    self.config['environment_type'] == Environment.PRODUCTION and
                    not self.config['unrecoverable_error_should_crash']
                )
                if log_unrecoverable:
                    log.error(str(e))
                else:
                    raise

        # Take a snapshot every SNAPSHOT_STATE_CHANGES_COUNT
        # TODO: Gather more data about storage requirements
        # and update the value to specify how often we need
        # capturing a snapshot should take place
        new_snapshot_group = self.wal.storage.count_state_changes() // SNAPSHOT_STATE_CHANGES_COUNT
        if new_snapshot_group > self.snapshot_group:
            log.debug('Storing snapshot', snapshot_id=new_snapshot_group)
            self.wal.snapshot()
            self.snapshot_group = new_snapshot_group

        return event_list

    def set_node_network_state(self, node_address, network_state):
        state_change = ActionChangeNodeNetworkState(node_address, network_state)
        self.handle_state_change(state_change)

    def start_health_check_for(self, node_address):
        # This function is a noop during initialization. It can be called
        # through the alarm task while polling for new channel events.  The
        # healthcheck will be started by self.start_neighbours_healthcheck()
        if self.transport:
            self.transport.start_health_check(node_address)

    def _callback_new_block(self, latest_block):
        """Called once a new block is detected by the alarm task.

        Note:
            This should be called only once per block, otherwise there will be
            duplicated `Block` state changes in the log.

            Therefore this method should be called only once a new block is
            mined with the corresponding block data from the AlarmTask.
        """
        # User facing APIs, which have on-chain side-effects, force polled the
        # blockchain to update the node's state. This force poll is used to
        # provide a consistent view to the user, e.g. a channel open call waits
        # for the transaction to be mined and force polled the event to update
        # the node's state. This pattern introduced a race with the alarm task
        # and the task which served the user request, because the events are
        # returned only once per filter. The lock below is to protect against
        # these races (introduced by the commit
        # 3686b3275ff7c0b669a6d5e2b34109c3bdf1921d)
        with self.event_poll_lock:
            latest_block_number = latest_block['number']
            confirmation_blocks = self.config['blockchain']['confirmation_blocks']
            confirmed_block_number = latest_block_number - confirmation_blocks
            confirmed_block = self.chain.client.web3.eth.getBlock(confirmed_block_number)

            # handle testing private chains
            confirmed_block_number = max(GENESIS_BLOCK_NUMBER, confirmed_block_number)

            for event in self.blockchain_events.poll_blockchain_events(confirmed_block_number):
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
                block_number=confirmed_block_number,
                gas_limit=confirmed_block['gasLimit'],
                block_hash=bytes(confirmed_block['hash']),
            )
            self.handle_state_change(state_change)

    def _register_payment_status(
            self,
            target: typing.TargetAddress,
            identifier: typing.PaymentID,
            payment_type: PaymentType,
            balance_proof: BalanceProofUnsignedState,
    ):
        self.targets_to_identifiers_to_statuses[target][identifier] = PaymentStatus(
            payment_type=payment_type,
            payment_identifier=identifier,
            amount=balance_proof.transferred_amount,
            token_network_identifier=balance_proof.token_network_identifier,
            payment_done=AsyncResult(),
        )

    def _initialize_transactions_queues(self, chain_state):
        pending_transactions = views.get_pending_transactions(chain_state)

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
                except InvalidDBData:
                    raise
                except RaidenUnrecoverableError as e:
                    log_unrecoverable = (
                        self.config['environment_type'] == Environment.PRODUCTION and
                        not self.config['unrecoverable_error_should_crash']
                    )
                    if log_unrecoverable:
                        log.error(str(e))
                    else:
                        raise

    def _initialize_messages_queues(self, chain_state):
        """ Push the queues to the transport and populate
        targets_to_identifiers_to_statuses.
        """
        events_queues = views.get_all_messagequeues(chain_state)

        for queue_identifier, event_queue in events_queues.items():
            self.start_health_check_for(queue_identifier.recipient)

            for event in event_queue:
                is_initiator = (
                    type(event) == SendLockedTransfer and
                    event.transfer.initiator == self.address
                )

                if type(event) == SendDirectTransfer:
                    self._register_payment_status(
                        target=event.recipient,
                        identifier=event.payment_identifier,
                        payment_type=PaymentType.DIRECT,
                        balance_proof=event.balance_proof,
                    )
                elif is_initiator:
                    self._register_payment_status(
                        target=event.transfer.target,
                        identifier=event.transfer.payment_identifier,
                        payment_type=PaymentType.MEDIATED,
                        balance_proof=event.transfer.balance_proof,
                    )

                message = message_from_sendevent(event, self.address)
                self.sign(message)
                self.transport.send_async(queue_identifier, message)

    def _initialize_whitelists(self, chain_state):
        """ Whitelist neighbors and mediated transfer targets on transport """

        for neighbour in views.all_neighbour_nodes(chain_state):
            if neighbour == ConnectionManager.BOOTSTRAP_ADDR:
                continue
            self.transport.whitelist(neighbour)

        events_queues = views.get_all_messagequeues(chain_state)

        for event_queue in events_queues.values():
            for event in event_queue:
                is_initiator = (
                    type(event) == SendLockedTransfer and
                    event.transfer.initiator == self.address
                )
                if is_initiator:
                    self.transport.whitelist(address=event.transfer.target)

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
                token_network_registry_proxy=token_network_registry_proxy,
                contract_manager=self.contract_manager,
                from_block=from_block,
            )
            self.blockchain_events.add_secret_registry_listener(
                secret_registry_proxy=secret_registry_proxy,
                contract_manager=self.contract_manager,
                from_block=from_block,
            )

            for token_network in token_networks:
                token_network_proxy = self.chain.token_network(token_network)
                self.blockchain_events.add_token_network_listener(
                    token_network_proxy=token_network_proxy,
                    contract_manager=self.contract_manager,
                    from_block=from_block,
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
        self.handle_state_change(state_change)

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

        secret = random_secret()
        async_result = self.start_mediated_transfer_with_secret(
            token_network_identifier,
            amount,
            target,
            identifier,
            secret,
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

        payment_status = self.targets_to_identifiers_to_statuses[target].get(identifier)
        if payment_status:
            if not payment_status.matches(PaymentType.DIRECT, token_network_identifier, amount):
                raise PaymentConflict(
                    'Another payment with the same id is in flight',
                )

            return payment_status.payment_done

        direct_transfer = ActionTransferDirect(
            token_network_identifier,
            target,
            identifier,
            amount,
        )

        payment_status = PaymentStatus(
            payment_type=PaymentType.DIRECT,
            payment_identifier=identifier,
            amount=amount,
            token_network_identifier=token_network_identifier,
            payment_done=AsyncResult(),
        )
        self.targets_to_identifiers_to_statuses[target][identifier] = payment_status

        self.handle_state_change(direct_transfer)

        return payment_status.payment_done

    def start_mediated_transfer_with_secret(
            self,
            token_network_identifier: typing.TokenNetworkID,
            amount: typing.TokenAmount,
            target: typing.Address,
            identifier: typing.PaymentID,
            secret: typing.Secret,
    ):

        secret_hash = sha3(secret)
        if self.default_secret_registry.check_registered(secret_hash):
            raise RaidenUnrecoverableError(
                f'Attempted to initiate a locked transfer with secrethash {pex(secret_hash)}.'
                f' That secret is already registered onchain.',
            )

        self.start_health_check_for(target)

        if identifier is None:
            identifier = create_default_identifier()

        payment_status = self.targets_to_identifiers_to_statuses[target].get(identifier)
        if payment_status:
            if not payment_status.matches(PaymentType.MEDIATED, token_network_identifier, amount):
                raise PaymentConflict(
                    'Another payment with the same id is in flight',
                )

            return payment_status.payment_done

        payment_status = PaymentStatus(
            payment_type=PaymentType.MEDIATED,
            payment_identifier=identifier,
            amount=amount,
            token_network_identifier=token_network_identifier,
            payment_done=AsyncResult(),
        )
        self.targets_to_identifiers_to_statuses[target][identifier] = payment_status

        init_initiator_statechange = initiator_init(
            raiden=self,
            transfer_identifier=identifier,
            transfer_amount=amount,
            transfer_secret=secret,
            token_network_identifier=token_network_identifier,
            target_address=target,
        )

        # Dispatch the state change even if there are no routes to create the
        # wal entry.
        self.handle_state_change(init_initiator_statechange)

        return payment_status.payment_done

    def mediate_mediated_transfer(self, transfer: LockedTransfer):
        init_mediator_statechange = mediator_init(self, transfer)
        self.handle_state_change(init_mediator_statechange)

    def target_mediated_transfer(self, transfer: LockedTransfer):
        self.start_health_check_for(transfer.initiator)
        init_target_statechange = target_init(transfer)
        self.handle_state_change(init_target_statechange)
