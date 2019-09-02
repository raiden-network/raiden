# pylint: disable=too-many-lines
import os
import random
from collections import defaultdict
from typing import Any, Dict, List, NamedTuple, Tuple
from uuid import UUID

import filelock
import gevent
import structlog
from eth_utils import is_binary_address, to_checksum_address, to_hex
from gevent import Greenlet
from gevent.event import AsyncResult, Event

from raiden import constants, routing
from raiden.blockchain.decode import (
    actionchannelupdatefee_from_channelstate,
    blockchainevent_to_statechange,
)
from raiden.blockchain.events import BlockchainEvents
from raiden.blockchain_events_handler import after_blockchain_statechange
from raiden.connection_manager import ConnectionManager
from raiden.constants import (
    ABSENT_SECRET,
    GENESIS_BLOCK_NUMBER,
    SECRET_LENGTH,
    SNAPSHOT_STATE_CHANGES_COUNT,
    Environment,
    RoutingMode,
)
from raiden.exceptions import (
    BrokenPreconditionError,
    InvalidBinaryAddress,
    InvalidDBData,
    InvalidSecret,
    InvalidSecretHash,
    PaymentConflict,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
)
from raiden.message_handler import MessageHandler
from raiden.messages.abstract import Message, SignedMessage
from raiden.messages.decode import lockedtransfersigned_from_message
from raiden.messages.encode import message_from_sendevent
from raiden.messages.transfers import LockedTransfer
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.network.proxies.user_deposit import UserDeposit
from raiden.network.transport.matrix.transport import MatrixTransport
from raiden.raiden_event_handler import EventHandler
from raiden.services import (
    update_monitoring_service_from_balance_proof,
    update_services_from_balance_proof,
)
from raiden.settings import MEDIATION_FEE, MediationFeeConfig
from raiden.storage import sqlite, wal
from raiden.storage.serialization import DictSerializer, JSONSerializer
from raiden.storage.wal import WriteAheadLog
from raiden.tasks import AlarmTask
from raiden.transfer import node, views
from raiden.transfer.architecture import BalanceProofSignedState, Event as RaidenEvent, StateChange
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.events import SendLockedTransfer
from raiden.transfer.mediated_transfer.state import TransferDescriptionWithSecretState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ActionInitTarget,
)
from raiden.transfer.mediated_transfer.tasks import InitiatorTask
from raiden.transfer.state import ChainState, HopState, TokenNetworkRegistryState
from raiden.transfer.state_change import (
    ActionChangeNodeNetworkState,
    ActionChannelWithdraw,
    ActionInitChain,
    Block,
    ContractReceiveNewTokenNetworkRegistry,
)
from raiden.utils import lpex, random_secret
from raiden.utils.logging import redact_secret
from raiden.utils.runnable import Runnable
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.signer import LocalSigner, Signer
from raiden.utils.typing import (
    Address,
    BlockHash,
    BlockNumber,
    BlockTimeout,
    FeeAmount,
    InitiatorAddress,
    Optional,
    PaymentAmount,
    PaymentID,
    Secret,
    SecretHash,
    TargetAddress,
    TokenNetworkAddress,
    WithdrawAmount,
)
from raiden.utils.upgrades import UpgradeManager
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)
StatusesDict = Dict[TargetAddress, Dict[PaymentID, "PaymentStatus"]]
ConnectionManagerDict = Dict[TokenNetworkAddress, ConnectionManager]


def initiator_init(
    raiden: "RaidenService",
    transfer_identifier: PaymentID,
    transfer_amount: PaymentAmount,
    transfer_secret: Secret,
    transfer_secrethash: SecretHash,
    transfer_fee: FeeAmount,
    token_network_address: TokenNetworkAddress,
    target_address: TargetAddress,
) -> ActionInitInitiator:
    transfer_state = TransferDescriptionWithSecretState(
        token_network_registry_address=raiden.default_registry.address,
        payment_identifier=transfer_identifier,
        amount=transfer_amount,
        allocated_fee=transfer_fee,
        token_network_address=token_network_address,
        initiator=InitiatorAddress(raiden.address),
        target=target_address,
        secret=transfer_secret,
        secrethash=transfer_secrethash,
    )

    routes, feedback_token = routing.get_best_routes(
        chain_state=views.state_from_raiden(raiden),
        token_network_address=token_network_address,
        one_to_n_address=raiden.default_one_to_n_address,
        from_address=InitiatorAddress(raiden.address),
        to_address=target_address,
        amount=transfer_amount,
        previous_address=None,
        config=raiden.config,
        privkey=raiden.privkey,
    )

    # Only prepare feedback when token is available
    if feedback_token is not None:
        for route_state in routes:
            raiden.route_to_feedback_token[tuple(route_state.route)] = feedback_token

    return ActionInitInitiator(transfer_state, routes)


def mediator_init(raiden: "RaidenService", transfer: LockedTransfer) -> ActionInitMediator:
    assert transfer.sender, "transfer must be signed"

    from_transfer = lockedtransfersigned_from_message(transfer)
    from_hop = HopState(
        transfer.sender,
        # pylint: disable=E1101
        from_transfer.balance_proof.channel_identifier,
    )
    route_states = routing.resolve_routes(
        routes=transfer.metadata.routes,
        # pylint: disable=E1101
        token_network_address=from_transfer.balance_proof.token_network_address,
        chain_state=views.state_from_raiden(raiden),
    )

    init_mediator_statechange = ActionInitMediator(
        from_hop=from_hop,
        route_states=route_states,
        from_transfer=from_transfer,
        balance_proof=from_transfer.balance_proof,
        sender=from_transfer.balance_proof.sender,  # pylint: disable=no-member
    )
    return init_mediator_statechange


def target_init(transfer: LockedTransfer) -> ActionInitTarget:
    assert transfer.sender, "transfer must be signed"

    from_transfer = lockedtransfersigned_from_message(transfer)
    from_hop = HopState(
        node_address=transfer.sender,
        # pylint: disable=E1101
        channel_identifier=from_transfer.balance_proof.channel_identifier,
    )
    init_target_statechange = ActionInitTarget(
        from_hop=from_hop,
        transfer=from_transfer,
        balance_proof=from_transfer.balance_proof,
        sender=from_transfer.balance_proof.sender,  # pylint: disable=no-member
    )
    return init_target_statechange


class PaymentStatus(NamedTuple):
    """Value type for RaidenService.targets_to_identifiers_to_statuses.

    Contains the necessary information to tell conflicting transfers from
    retries as well as the status of a transfer that is retried.
    """

    payment_identifier: PaymentID
    amount: PaymentAmount
    token_network_address: TokenNetworkAddress
    payment_done: AsyncResult

    def matches(self, token_network_address: TokenNetworkAddress, amount: PaymentAmount) -> bool:
        return token_network_address == self.token_network_address and amount == self.amount


class RaidenService(Runnable):
    """ A Raiden node. """

    def __init__(
        self,
        chain: BlockChainService,
        query_start_block: BlockNumber,
        default_registry: TokenNetworkRegistry,
        default_secret_registry: SecretRegistry,
        default_service_registry: Optional[ServiceRegistry],
        default_one_to_n_address: Optional[Address],
        default_msc_address: Address,
        transport: MatrixTransport,
        raiden_event_handler: EventHandler,
        message_handler: MessageHandler,
        routing_mode: RoutingMode,
        config: Dict[str, Any],
        user_deposit: UserDeposit = None,
    ) -> None:
        super().__init__()
        self.tokennetworkaddrs_to_connectionmanagers: ConnectionManagerDict = dict()
        self.targets_to_identifiers_to_statuses: StatusesDict = defaultdict(dict)

        self.chain: BlockChainService = chain
        self.default_registry = default_registry
        self.query_start_block = query_start_block
        self.default_one_to_n_address = default_one_to_n_address
        self.default_secret_registry = default_secret_registry
        self.default_service_registry = default_service_registry
        self.default_msc_address = default_msc_address
        self.routing_mode = routing_mode
        self.config = config

        self.signer: Signer = LocalSigner(self.chain.client.privkey)
        self.address = self.signer.address
        self.transport = transport

        self.user_deposit = user_deposit

        self.blockchain_events = BlockchainEvents(self.chain.network_id)
        self.alarm = AlarmTask(chain)
        self.raiden_event_handler = raiden_event_handler
        self.message_handler = message_handler

        self.stop_event = Event()
        self.stop_event.set()  # inits as stopped
        self.greenlets: List[Greenlet] = list()

        self.snapshot_group = 0

        self.contract_manager = ContractManager(config["contracts_path"])
        self.database_path = config["database_path"]
        self.wal: Optional[WriteAheadLog] = None
        if self.database_path != ":memory:":
            database_dir = os.path.dirname(config["database_path"])
            os.makedirs(database_dir, exist_ok=True)

            self.database_dir = database_dir

            # Two raiden processes must not write to the same database. Even
            # though it's possible the database itself would not be corrupt,
            # the node's state could. If a database was shared among multiple
            # nodes, the database WAL would be the union of multiple node's
            # WAL. During a restart a single node can't distinguish its state
            # changes from the others, and it would apply it all, meaning that
            # a node would execute the actions of itself and the others.
            #
            # Additionally the database snapshots would be corrupt, because it
            # would not represent the effects of applying all the state changes
            # in order.
            lock_file = os.path.join(self.database_dir, ".lock")
            self.db_lock = filelock.FileLock(lock_file)
        else:
            self.database_path = ":memory:"
            self.database_dir = None
            self.serialization_file = None
            self.db_lock = None

        self.event_poll_lock = gevent.lock.Semaphore()
        self.gas_reserve_lock = gevent.lock.Semaphore()
        self.payment_identifier_lock = gevent.lock.Semaphore()

        # A list is not hashable, so use tuple as key here
        self.route_to_feedback_token: Dict[Tuple[Address, ...], UUID] = dict()

        # Flag used to skip the processing of all Raiden events during the
        # startup.
        #
        # Rationale: At the startup, the latest snapshot is restored and all
        # state changes which are not 'part' of it are applied. The criteria to
        # re-apply the state changes is their 'absence' in the snapshot, /not/
        # their completeness. Because these state changes are re-executed
        # in-order and some of their side-effects will already have been
        # completed, the events should be delayed until the state is
        # synchronized (e.g. an open channel state change, which has already
        # been mined).
        #
        # Incomplete events, i.e. the ones which don't have their side-effects
        # applied, will be executed once the blockchain state is synchronized
        # because of the node's queues.
        self.ready_to_process_events = False

    def start(self) -> None:
        """ Start the node synchronously. Raises directly if anything went wrong on startup """
        assert self.stop_event.ready(), f"Node already started. node:{self!r}"
        self.stop_event.clear()
        self.greenlets = list()

        self.ready_to_process_events = False  # set to False because of restarts

        if self.database_dir is not None:
            self.db_lock.acquire(timeout=0)
            assert self.db_lock.is_locked, f"Database not locked. node:{self!r}"

        self.maybe_upgrade_db()

        storage = sqlite.SerializedSQLiteStorage(
            database_path=self.database_path, serializer=JSONSerializer()
        )
        storage.update_version()
        storage.log_run()
        self.wal = wal.restore_to_state_change(
            transition_function=node.state_transition,
            storage=storage,
            state_change_identifier=sqlite.HIGH_STATECHANGE_ULID,
            node_address=self.address,
        )

        if self.wal.state_manager.current_state is None:
            log.debug(
                "No recoverable state available, creating inital state.",
                node=to_checksum_address(self.address),
            )
            # On first run Raiden needs to fetch all events for the payment
            # network, to reconstruct all token network graphs and find opened
            # channels
            last_log_block_number = self.query_start_block
            last_log_block_hash = self.chain.client.blockhash_from_blocknumber(
                last_log_block_number
            )

            init_state_change = ActionInitChain(
                pseudo_random_generator=random.Random(),
                block_number=last_log_block_number,
                block_hash=last_log_block_hash,
                our_address=self.chain.node_address,
                chain_id=self.chain.network_id,
            )
            token_network_registry = TokenNetworkRegistryState(
                self.default_registry.address,
                [],  # empty list of token network states as it's the node's startup
            )
            new_network_state_change = ContractReceiveNewTokenNetworkRegistry(
                transaction_hash=constants.EMPTY_TRANSACTION_HASH,
                token_network_registry=token_network_registry,
                block_number=last_log_block_number,
                block_hash=last_log_block_hash,
            )

            self.handle_and_track_state_changes([init_state_change, new_network_state_change])
        else:
            # The `Block` state change is dispatched only after all the events
            # for that given block have been processed, filters can be safely
            # installed starting from this position without losing events.
            last_log_block_number = views.block_number(self.wal.state_manager.current_state)
            log.debug(
                "Restored state from WAL",
                last_restored_block=last_log_block_number,
                node=to_checksum_address(self.address),
            )

            known_networks = views.get_token_network_registry_address(
                views.state_from_raiden(self)
            )
            if known_networks and self.default_registry.address not in known_networks:
                configured_registry = to_checksum_address(self.default_registry.address)
                known_registries = lpex(known_networks)
                raise RuntimeError(
                    f"Token network address mismatch.\n"
                    f"Raiden is configured to use the smart contract "
                    f"{configured_registry}, which conflicts with the current known "
                    f"smart contracts {known_registries}"
                )

        # Restore the current snapshot group
        state_change_qty = self.wal.storage.count_state_changes()
        self.snapshot_group = state_change_qty // SNAPSHOT_STATE_CHANGES_COUNT

        # Install the filters using the latest confirmed from_block value,
        # otherwise blockchain logs can be lost.
        self.install_all_blockchain_filters(
            self.default_registry, self.default_secret_registry, last_log_block_number
        )
        self._prepare_and_execute_alarm_first_run(last_log_block=last_log_block_number)

        chain_state = views.state_from_raiden(self)

        # This must happen after DB had been initialized and the alarm task's first run
        self._initialize_payment_statuses(chain_state)
        self._initialize_transactions_queues(chain_state)
        self._initialize_messages_queues(chain_state)
        self._initialize_whitelists(chain_state)
        self._initialize_channel_fees()
        self._initialize_monitoring_services_queue(chain_state)
        self._initialize_ready_to_process_events()

        # Start the side-effects:
        # - React to blockchain events
        # - React to incoming messages
        # - Send pending transactions
        # - Send pending message
        self.alarm.link_exception(self.on_error)
        self.transport.link_exception(self.on_error)
        self._start_transport(chain_state)
        self._start_alarm_task()

        log.debug("Raiden Service started", node=to_checksum_address(self.address))
        super().start()

    def _run(self, *args: Any, **kwargs: Any) -> None:  # pylint: disable=method-hidden
        """ Busy-wait on long-lived subtasks/greenlets, re-raise if any error occurs """
        self.greenlet.name = f"RaidenService._run node:{to_checksum_address(self.address)}"
        try:
            self.stop_event.wait()
        except gevent.GreenletExit:  # killed without exception
            self.stop_event.set()
            gevent.killall([self.alarm, self.transport])  # kill children
            raise  # re-raise to keep killed status
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
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

        # Close storage DB to release internal DB lock
        assert self.wal, "The Service must have been started before it can be stopped"
        self.wal.storage.close()
        self.wal = None

        if self.db_lock is not None:
            self.db_lock.release()

        log.debug("Raiden Service stopped", node=to_checksum_address(self.address))

    @property
    def confirmation_blocks(self) -> BlockTimeout:
        return self.config["blockchain"]["confirmation_blocks"]

    @property
    def privkey(self) -> bytes:
        return self.chain.client.privkey

    def add_pending_greenlet(self, greenlet: Greenlet) -> None:
        """ Ensures an error on the passed greenlet crashes self/main greenlet. """

        def remove(_: Any) -> None:
            self.greenlets.remove(greenlet)

        self.greenlets.append(greenlet)
        greenlet.link_exception(self.on_error)
        greenlet.link_value(remove)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} node:{to_checksum_address(self.address)}>"

    def _start_transport(self, chain_state: ChainState) -> None:
        """ Initialize the transport and related facilities.

        Note:
            The transport must not be started before the node has caught up
            with the blockchain through `AlarmTask.first_run()`. This
            synchronization includes the on-chain channel state and is
            necessary to reject new messages for closed channels.
        """
        assert self.alarm.is_primed(), f"AlarmTask not primed. node:{self!r}"
        assert self.ready_to_process_events, f"Event procossing disable. node:{self!r}"

        self.transport.start(
            raiden_service=self,
            message_handler=self.message_handler,
            prev_auth_data=chain_state.last_transport_authdata,
        )

        for neighbour in views.all_neighbour_nodes(chain_state):
            if neighbour != ConnectionManager.BOOTSTRAP_ADDR:
                self.start_health_check_for(neighbour)

    def _prepare_and_execute_alarm_first_run(self, last_log_block: BlockNumber) -> None:
        """Prepares the alarm task callback and executes its first run

        Complete the first_run of the alarm task and synchronize with the
        blockchain since the last run.

         Notes about setup order:
         - The filters must be polled after the node state has been primed,
           otherwise the state changes won't have effect.
         - The alarm must complete its first run before the transport is started,
           to reject messages for closed/settled channels.
        """
        assert not self.transport, f"Transport is running. node:{self!r}"
        assert self.wal, "The database must have been initialized. node:{self!r}"

        self.alarm.register_callback(self._callback_new_block)
        self.alarm.first_run(last_log_block)
        # The first run of the alarm task processes some state changes and may add
        # new token network event filters when this is the first time Raiden runs.
        # Here we poll for any new events that may exist after the addition of
        # those event filters.
        latest_block_num = self.chain.get_block(block_identifier="latest")["number"]
        latest_confirmed_block_num = max(
            GENESIS_BLOCK_NUMBER, latest_block_num - self.confirmation_blocks
        )

        blockchain_events = self.blockchain_events.poll_blockchain_events(
            latest_confirmed_block_num
        )

        state_changes = []
        for event in blockchain_events:
            state_changes.extend(
                blockchainevent_to_statechange(self, event, latest_confirmed_block_num)
            )
        self.handle_and_track_state_changes(state_changes)

    def _start_alarm_task(self) -> None:
        """Start the alarm task.

        Note:
            The alarm task must be started only when processing events is
            allowed, otherwise side-effects of blockchain events will be
            ignored.
        """
        assert self.ready_to_process_events, f"Event processing disabled. node:{self!r}"
        self.alarm.start()

    def _initialize_ready_to_process_events(self) -> None:
        assert not self.transport
        assert not self.alarm

        # This flag /must/ be set to true before the transport or the alarm task is started
        self.ready_to_process_events = True

    def get_block_number(self) -> BlockNumber:
        assert self.wal, f"WAL object not yet initialized. node:{self!r}"
        return views.block_number(self.wal.state_manager.current_state)  # type: ignore

    def on_message(self, message: Message) -> None:
        self.message_handler.on_message(self, message)

    def handle_and_track_state_changes(self, state_changes: List[StateChange]) -> None:
        """ Dispatch the state change and does not handle the exceptions.

        When the method is used the exceptions are tracked and re-raised in the
        raiden service thread.
        """
        if len(state_changes) == 0:
            return

        for greenlet in self.handle_state_changes(state_changes):
            self.add_pending_greenlet(greenlet)

    def handle_state_changes(self, state_changes: List[StateChange]) -> List[Greenlet]:
        """ Dispatch the state change and return the processing threads.

        Use this for error reporting, failures in the returned greenlets,
        should be re-raised using `gevent.joinall` with `raise_error=True`.
        """
        assert self.wal, f"WAL not restored. node:{self!r}"
        log.debug(
            "State changes",
            node=to_checksum_address(self.address),
            state_changes=[
                redact_secret(DictSerializer.serialize(state_change))
                for state_change in state_changes
            ],
        )

        old_state = views.state_from_raiden(self)
        new_state, raiden_event_list = self.wal.log_and_dispatch(state_changes)

        for state_change in state_changes:
            after_blockchain_statechange(self, state_change)

        for changed_balance_proof in views.detect_balance_proof_change(old_state, new_state):
            update_services_from_balance_proof(self, new_state, changed_balance_proof)

        log.debug(
            "Raiden events",
            node=to_checksum_address(self.address),
            raiden_events=[
                redact_secret(DictSerializer.serialize(event)) for event in raiden_event_list
            ],
        )

        greenlets: List[Greenlet] = list()
        if self.ready_to_process_events:
            for raiden_event in raiden_event_list:
                greenlets.append(
                    self.handle_event(chain_state=new_state, raiden_event=raiden_event)
                )

            state_changes_count = self.wal.storage.count_state_changes()
            new_snapshot_group = state_changes_count // SNAPSHOT_STATE_CHANGES_COUNT
            if new_snapshot_group > self.snapshot_group:
                log.debug("Storing snapshot", snapshot_id=new_snapshot_group)
                self.wal.snapshot()
                self.snapshot_group = new_snapshot_group

        return greenlets

    def handle_event(self, chain_state: ChainState, raiden_event: RaidenEvent) -> Greenlet:
        """Spawn a new thread to handle a Raiden event.

        This will spawn a new greenlet to handle each event, which is
        important for two reasons:

        - Blockchain transactions can be queued without interfering with each
          other.
        - The calling thread is free to do more work. This is specially
          important for the AlarmTask thread, which will eventually cause the
          node to send transactions when a given Block is reached (e.g.
          registering a secret or settling a channel).

        Important:

            This is spawing a new greenlet for /each/ transaction. It's
            therefore /required/ that there is *NO* order among these.
        """
        return gevent.spawn(self._handle_event, chain_state, raiden_event)

    def _handle_event(self, chain_state: ChainState, raiden_event: RaidenEvent) -> None:
        assert isinstance(chain_state, ChainState)
        assert isinstance(raiden_event, RaidenEvent)

        try:
            self.raiden_event_handler.on_raiden_event(
                raiden=self, chain_state=chain_state, event=raiden_event
            )
        except RaidenRecoverableError as e:
            log.error(str(e))
        except InvalidDBData:
            raise
        except RaidenUnrecoverableError as e:
            log_unrecoverable = (
                self.config["environment_type"] == Environment.PRODUCTION
                and not self.config["unrecoverable_error_should_crash"]
            )
            if log_unrecoverable:
                log.error(str(e))
            else:
                raise

    def set_node_network_state(self, node_address: Address, network_state: str) -> None:
        state_change = ActionChangeNodeNetworkState(node_address, network_state)
        self.handle_and_track_state_changes([state_change])

    def start_health_check_for(self, node_address: Address) -> None:
        """Start health checking `node_address`.

        This function is a noop during initialization, because health checking
        can be started as a side effect of some events (e.g. new channel). For
        these cases the healthcheck will be started by
        `start_neighbours_healthcheck`.
        """
        if self.transport:
            self.transport.start_health_check(node_address)

    def _callback_new_block(self, latest_block: Dict) -> None:
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
            latest_block_number = latest_block["number"]

            # Handle testing with private chains. The block number can be
            # smaller than confirmation_blocks
            latest_confirmed_block_number = max(
                GENESIS_BLOCK_NUMBER, latest_block_number - self.confirmation_blocks
            )
            latest_confirmed_block = self.chain.client.web3.eth.getBlock(
                latest_confirmed_block_number
            )

            state_changes: List[StateChange] = list()

            # On restarts the node has to pick up all events generated since the
            # last run. To do this the node will set the filters' from_block to
            # the value of the latest block number known to have *all* events
            # processed.
            #
            # To guarantee the above the node must either:
            #
            # - Dispatch the state changes individually, leaving the Block
            # state change last, so that it knows all the events for the
            # given block have been processed. On restarts this can result in
            # the same event being processed twice.
            # - Dispatch all the smart contract events together with the Block
            # state change in a single transaction, either all or nothing will
            # be applied, and on a restart the node picks up from where it
            # left.
            #
            # The approach used bellow is to dispatch the Block and the
            # blockchain events in a single transaction. This is the preferred
            # approach because it guarantees that no events will be missed and
            # it fixes race conditions on the value of the block number value,
            # that can lead to crashes.
            #
            # Example: The user creates a new channel with an initial deposit
            # of X tokens. This is done with two operations, the first is to
            # open the new channel, the second is to deposit the requested
            # tokens in it. Once the node fetches the event for the new channel,
            # it will immediately request the deposit, which leaves a window for
            # a race condition. If the Block state change was not yet
            # processed, the block hash used as the trigerring block for the
            # deposit will be off-by-one, and it will point to the block
            # immediately before the channel existed. This breaks a proxy
            # precondition which crashes the client.
            block_state_change = Block(
                block_number=latest_confirmed_block_number,
                gas_limit=latest_confirmed_block["gasLimit"],
                block_hash=BlockHash(bytes(latest_confirmed_block["hash"])),
            )
            state_changes.append(block_state_change)

            blockchain_events = self.blockchain_events.poll_blockchain_events(
                latest_confirmed_block_number
            )

            for event in blockchain_events:
                state_changes.extend(
                    blockchainevent_to_statechange(self, event, latest_confirmed_block_number)
                )

            # It's important to /not/ block here, because this function can be
            # called from the alarm task greenlet, which should not starve.
            #
            # All the state changes are dispatched together
            self.handle_and_track_state_changes(state_changes)

    def _initialize_transactions_queues(self, chain_state: ChainState) -> None:
        """Initialize the pending transaction queue from the previous run.

        Note:
            This will only send the transactions which don't have their
            side-effects applied. Transactions which another node may have sent
            already will be detected by the alarm task's first run and cleared
            from the queue (e.g. A monitoring service update transfer).
        """
        assert self.alarm.is_primed(), f"AlarmTask not primed. node:{self!r}"

        pending_transactions = views.get_pending_transactions(chain_state)

        log.debug(
            "Initializing transaction queues",
            num_pending_transactions=len(pending_transactions),
            node=to_checksum_address(self.address),
        )

        for transaction in pending_transactions:
            try:
                self.raiden_event_handler.on_raiden_event(
                    raiden=self, chain_state=chain_state, event=transaction
                )
            except RaidenRecoverableError as e:
                log.error(str(e))
            except InvalidDBData:
                raise
            except (RaidenUnrecoverableError, BrokenPreconditionError) as e:
                log_unrecoverable = (
                    self.config["environment_type"] == Environment.PRODUCTION
                    and not self.config["unrecoverable_error_should_crash"]
                )
                if log_unrecoverable:
                    log.error(str(e))
                else:
                    raise

    def _initialize_payment_statuses(self, chain_state: ChainState) -> None:
        """ Re-initialize targets_to_identifiers_to_statuses.

        Restore the PaymentStatus for any pending payment. This is not tied to
        a specific protocol message but to the lifecycle of a payment, i.e.
        the status is re-created if a payment itself has not completed.
        """

        with self.payment_identifier_lock:
            secret_hashes = [
                to_hex(secrethash)
                for secrethash in chain_state.payment_mapping.secrethashes_to_task
            ]
            log.debug(
                "Initializing payment statuses",
                secret_hashes=secret_hashes,
                node=to_checksum_address(self.address),
            )

            for task in chain_state.payment_mapping.secrethashes_to_task.values():
                if not isinstance(task, InitiatorTask):
                    continue

                # Every transfer in the transfers_list must have the same target
                # and payment_identifier, so using the first transfer is
                # sufficient.
                initiator = next(iter(task.manager_state.initiator_transfers.values()))
                transfer = initiator.transfer
                transfer_description = initiator.transfer_description
                target = transfer.target
                identifier = transfer.payment_identifier
                balance_proof = transfer.balance_proof
                self.targets_to_identifiers_to_statuses[target][identifier] = PaymentStatus(
                    payment_identifier=identifier,
                    amount=transfer_description.amount,
                    token_network_address=balance_proof.token_network_address,
                    payment_done=AsyncResult(),
                )

    def _initialize_messages_queues(self, chain_state: ChainState) -> None:
        """Initialize all the message queues with the transport.

        Note:
            All messages from the state queues must be pushed to the transport
            before it's started. This is necessary to avoid a race where the
            transport processes network messages too quickly, queueing new
            messages before any of the previous messages, resulting in new
            messages being out-of-order.

            The Alarm task must be started before this method is called,
            otherwise queues for channel closed while the node was offline
            won't be properly cleared. It is not bad but it is suboptimal.
        """
        assert not self.transport, f"Transport is running. node:{self!r}"
        assert self.alarm.is_primed(), f"AlarmTask not primed. node:{self!r}"

        events_queues = views.get_all_messagequeues(chain_state)

        log.debug(
            "Initializing message queues",
            queues_identifiers=list(events_queues.keys()),
            node=to_checksum_address(self.address),
        )

        for queue_identifier, event_queue in events_queues.items():
            for event in event_queue:
                message = message_from_sendevent(event)
                self.sign(message)
                self.transport.send_async(queue_identifier, message)

    def _initialize_monitoring_services_queue(self, chain_state: ChainState) -> None:
        """Send the monitoring requests for all current balance proofs.

        Note:
            The node must always send the *received* balance proof to the
            monitoring service, *before* sending its own locked transfer
            forward. If the monitoring service is updated after, then the
            following can happen:

            For a transfer A-B-C where this node is B

            - B receives T1 from A and processes it
            - B forwards its T2 to C
            * B crashes (the monitoring service is not updated)

            For the above scenario, the monitoring service would not have the
            latest balance proof received by B from A available with the lock
            for T1, but C would. If the channel B-C is closed and B does not
            come back online in time, the funds for the lock L1 can be lost.

            During restarts the rationale from above has to be replicated.
            Because the initialization code *is not* the same as the event
            handler. This means the balance proof updates must be done prior to
            the processing of the message queues.
        """
        msg = (
            "Transport was started before the monitoring service queue was updated. "
            "This can lead to safety issue. node:{self!r}"
        )
        assert not self.transport, msg

        msg = "The node state was not yet recovered, cant read balance proofs. node:{self!r}"
        assert self.wal, msg

        current_balance_proofs = list(
            balance_proof
            for balance_proof in views.detect_balance_proof_change(
                old_state=ChainState(
                    pseudo_random_generator=chain_state.pseudo_random_generator,
                    block_number=GENESIS_BLOCK_NUMBER,
                    block_hash=constants.EMPTY_HASH,
                    our_address=chain_state.our_address,
                    chain_id=chain_state.chain_id,
                ),
                current_state=chain_state,
            )
            # only request monitoring for own BPs
            if isinstance(balance_proof, BalanceProofSignedState)
        )

        log.debug(
            "Initializing monitoring services",
            num_of_balance_proofs=len(current_balance_proofs),
            node=to_checksum_address(self.address),
        )

        for balance_proof in current_balance_proofs:
            update_monitoring_service_from_balance_proof(self, chain_state, balance_proof)

    def _initialize_whitelists(self, chain_state: ChainState) -> None:
        """ Whitelist neighbors and mediated transfer targets on transport """

        all_neighbour_nodes = views.all_neighbour_nodes(chain_state)

        log.debug(
            "Initializing whitelists",
            neighbour_nodes=[to_checksum_address(neighbour) for neighbour in all_neighbour_nodes],
            node=to_checksum_address(self.address),
        )

        for neighbour in all_neighbour_nodes:
            if neighbour == ConnectionManager.BOOTSTRAP_ADDR:
                continue
            self.transport.whitelist(neighbour)

        events_queues = views.get_all_messagequeues(chain_state)

        for event_queue in events_queues.values():
            for event in event_queue:
                if isinstance(event, SendLockedTransfer):
                    transfer = event.transfer
                    if transfer.initiator == self.address:
                        self.transport.whitelist(address=Address(transfer.target))

    def _initialize_channel_fees(self) -> None:
        """ Initializes the fees of all open channels to the latest set values.

        This includes a recalculation of the dynamic rebalancing fees.
        """
        chain_state = views.state_from_raiden(self)
        fee_config: MediationFeeConfig = self.config["mediation_fees"]
        token_addresses = views.get_token_identifiers(
            chain_state=chain_state, token_network_registry_address=self.default_registry.address
        )

        for token_address in token_addresses:
            channels = views.get_channelstate_open(
                chain_state=chain_state,
                token_network_registry_address=self.default_registry.address,
                token_address=token_address,
            )

            for channel in channels:
                # get the flat fee for this network if set, otherwise the default
                flat_fee = fee_config.get_flat_fee(channel.token_network_address)
                log.info(
                    "Updating channel fees",
                    channel=channel.canonical_identifier,
                    flat_fee=flat_fee,
                    proportional_fee=fee_config.proportional_fee,
                    proportional_imbalance_fee=fee_config.proportional_imbalance_fee,
                )

                state_change = actionchannelupdatefee_from_channelstate(
                    channel_state=channel,
                    flat_fee=flat_fee,
                    proportional_fee=fee_config.proportional_fee,
                    proportional_imbalance_fee=fee_config.proportional_imbalance_fee,
                )
                self.handle_and_track_state_changes([state_change])

    def sign(self, message: Message) -> None:
        """ Sign message inplace. """
        if not isinstance(message, SignedMessage):
            raise ValueError("{} is not signable.".format(repr(message)))

        message.sign(self.signer)

    def install_all_blockchain_filters(
        self,
        token_network_registry_proxy: TokenNetworkRegistry,
        secret_registry_proxy: SecretRegistry,
        from_block: BlockNumber,
    ) -> None:
        with self.event_poll_lock:
            node_state = views.state_from_raiden(self)
            token_networks = views.get_token_network_addresses(
                node_state, token_network_registry_proxy.address
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

            for token_network_address in token_networks:
                token_network_proxy = self.chain.token_network(token_network_address)
                self.blockchain_events.add_token_network_listener(
                    token_network_proxy=token_network_proxy,
                    contract_manager=self.contract_manager,
                    from_block=from_block,
                )

    def connection_manager_for_token_network(
        self, token_network_address: TokenNetworkAddress
    ) -> ConnectionManager:
        if not is_binary_address(token_network_address):
            raise InvalidBinaryAddress("token address is not valid.")

        known_token_networks = views.get_token_network_addresses(
            views.state_from_raiden(self), self.default_registry.address
        )

        if token_network_address not in known_token_networks:
            raise InvalidBinaryAddress("token is not registered.")

        manager = self.tokennetworkaddrs_to_connectionmanagers.get(token_network_address)

        if manager is None:
            manager = ConnectionManager(self, token_network_address)
            self.tokennetworkaddrs_to_connectionmanagers[token_network_address] = manager

        return manager

    def mediated_transfer_async(
        self,
        token_network_address: TokenNetworkAddress,
        amount: PaymentAmount,
        target: TargetAddress,
        identifier: PaymentID,
        fee: FeeAmount = MEDIATION_FEE,
        secret: Secret = None,
        secrethash: SecretHash = None,
    ) -> PaymentStatus:
        """ Transfer `amount` between this node and `target`.

        This method will start an asynchronous transfer, the transfer might fail
        or succeed depending on a couple of factors:

            - Existence of a path that can be used, through the usage of direct
              or intermediary channels.
            - Network speed, making the transfer sufficiently fast so it doesn't
              expire.
        """
        if secret is None:
            if secrethash is None:
                secret = random_secret()
            else:
                secret = ABSENT_SECRET

        payment_status = self.start_mediated_transfer_with_secret(
            token_network_address=token_network_address,
            amount=amount,
            fee=fee,
            target=target,
            identifier=identifier,
            secret=secret,
            secrethash=secrethash,
        )

        return payment_status

    def start_mediated_transfer_with_secret(
        self,
        token_network_address: TokenNetworkAddress,
        amount: PaymentAmount,
        fee: FeeAmount,
        target: TargetAddress,
        identifier: PaymentID,
        secret: Secret,
        secrethash: SecretHash = None,
    ) -> PaymentStatus:

        if secrethash is None:
            secrethash = sha256_secrethash(secret)
        elif secrethash != sha256_secrethash(secret):
            raise InvalidSecretHash("provided secret and secret_hash do not match.")

        if len(secret) != SECRET_LENGTH:
            raise InvalidSecret("secret of invalid length.")

        log.debug(
            "Mediated transfer",
            node=self.address,
            target=target,
            amount=amount,
            identifier=identifier,
            fee=fee,
            token_network_address=token_network_address,
        )

        # We must check if the secret was registered against the latest block,
        # even if the block is forked away and the transaction that registers
        # the secret is removed from the blockchain. The rationale here is that
        # someone else does know the secret, regardless of the chain state, so
        # the node must not use it to start a payment.
        #
        # For this particular case, it's preferable to use `latest` instead of
        # having a specific block_hash, because it's preferable to know if the secret
        # was ever known, rather than having a consistent view of the blockchain.
        secret_registered = self.default_secret_registry.is_secret_registered(
            secrethash=secrethash, block_identifier="latest"
        )
        if secret_registered:
            raise RaidenUnrecoverableError(
                f"Attempted to initiate a locked transfer with secrethash {to_hex(secrethash)}."
                f" That secret is already registered onchain."
            )

        self.start_health_check_for(Address(target))

        with self.payment_identifier_lock:
            payment_status = self.targets_to_identifiers_to_statuses[target].get(identifier)
            if payment_status:
                payment_status_matches = payment_status.matches(token_network_address, amount)
                if not payment_status_matches:
                    raise PaymentConflict("Another payment with the same id is in flight")

                return payment_status

            payment_status = PaymentStatus(
                payment_identifier=identifier,
                amount=amount,
                token_network_address=token_network_address,
                payment_done=AsyncResult(),
            )
            self.targets_to_identifiers_to_statuses[target][identifier] = payment_status

        init_initiator_statechange = initiator_init(
            raiden=self,
            transfer_identifier=identifier,
            transfer_amount=amount,
            transfer_secret=secret,
            transfer_secrethash=secrethash,
            transfer_fee=fee,
            token_network_address=token_network_address,
            target_address=target,
        )

        # Dispatch the state change even if there are no routes to create the
        # wal entry.
        self.handle_and_track_state_changes([init_initiator_statechange])

        return payment_status

    def mediate_mediated_transfer(self, transfer: LockedTransfer) -> None:
        init_mediator_statechange = mediator_init(self, transfer)
        self.handle_and_track_state_changes([init_mediator_statechange])

    def target_mediated_transfer(self, transfer: LockedTransfer) -> None:
        self.start_health_check_for(Address(transfer.initiator))
        init_target_statechange = target_init(transfer)
        self.handle_and_track_state_changes([init_target_statechange])

    def withdraw(
        self, canonical_identifier: CanonicalIdentifier, total_withdraw: WithdrawAmount
    ) -> None:
        init_withdraw = ActionChannelWithdraw(
            canonical_identifier=canonical_identifier, total_withdraw=total_withdraw
        )

        self.handle_and_track_state_changes([init_withdraw])

    def maybe_upgrade_db(self) -> None:
        manager = UpgradeManager(
            db_filename=self.database_path, raiden=self, web3=self.chain.client.web3
        )
        manager.run()
