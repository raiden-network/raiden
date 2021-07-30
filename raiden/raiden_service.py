# pylint: disable=too-many-lines
import os
import random
import time
from collections import defaultdict
from enum import Enum
from typing import Any, Dict, List, NamedTuple, Set, Tuple, cast
from uuid import UUID

import click
import filelock
import gevent
import structlog
from eth_utils import to_hex
from gevent import Greenlet
from gevent.event import AsyncResult, Event
from web3.types import BlockData

from raiden import routing
from raiden.api.objects import Notification
from raiden.api.python import RaidenAPI
from raiden.api.rest import APIServer, RestAPI
from raiden.blockchain.decode import blockchainevent_to_statechange
from raiden.blockchain.events import BlockchainEvents, DecodedEvent
from raiden.blockchain.filters import RaidenContractFilter
from raiden.constants import (
    ABSENT_SECRET,
    BLOCK_ID_LATEST,
    GENESIS_BLOCK_NUMBER,
    SECRET_LENGTH,
    SNAPSHOT_STATE_CHANGES_COUNT,
    Environment,
    RoutingMode,
)
from raiden.exceptions import (
    BrokenPreconditionError,
    InvalidDBData,
    InvalidSecret,
    InvalidSecretHash,
    InvalidSettleTimeout,
    PaymentConflict,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
    SerializationError,
)
from raiden.message_handler import MessageHandler
from raiden.messages.abstract import Message, SignedMessage
from raiden.messages.encode import message_from_sendevent
from raiden.network.pathfinding import PFSProxy
from raiden.network.proxies.proxy_manager import ProxyManager
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.network.proxies.user_deposit import UserDeposit
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.transport import populate_services_addresses
from raiden.network.transport.matrix.transport import MatrixTransport, MessagesQueue
from raiden.raiden_event_handler import EventHandler
from raiden.services import send_pfs_update, update_monitoring_service_from_balance_proof
from raiden.settings import RaidenConfig
from raiden.storage import sqlite, wal
from raiden.storage.serialization import DictSerializer, JSONSerializer
from raiden.storage.sqlite import HIGH_STATECHANGE_ULID, Range
from raiden.storage.wal import WriteAheadLog
from raiden.tasks import AlarmTask
from raiden.transfer import node, views
from raiden.transfer.architecture import (
    BalanceProofSignedState,
    ContractSendEvent,
    Event as RaidenEvent,
    StateChange,
)
from raiden.transfer.channel import get_capacity
from raiden.transfer.events import (
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
    EventWrapper,
    RequestMetadata,
    SendWithdrawExpired,
    SendWithdrawRequest,
)
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.events import (
    EventRouteFailed,
    SendLockedTransfer,
    SendSecretRequest,
    SendUnlock,
)
from raiden.transfer.mediated_transfer.mediation_fee import (
    FeeScheduleState,
    calculate_imbalance_fees,
)
from raiden.transfer.mediated_transfer.state import TransferDescriptionWithSecretState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ReceiveLockExpired,
    ReceiveTransferCancelRoute,
    ReceiveTransferRefund,
)
from raiden.transfer.mediated_transfer.tasks import InitiatorTask
from raiden.transfer.state import ChainState, RouteState, TokenNetworkRegistryState
from raiden.transfer.state_change import (
    ActionChannelSetRevealTimeout,
    ActionChannelWithdraw,
    BalanceProofStateChange,
    Block,
    ContractReceiveChannelDeposit,
    ReceiveUnlock,
    ReceiveWithdrawExpired,
    ReceiveWithdrawRequest,
)
from raiden.ui.startup import RaidenBundle, ServicesBundle
from raiden.utils.formatting import lpex, to_checksum_address
from raiden.utils.gevent import spawn_named
from raiden.utils.logging import redact_secret
from raiden.utils.runnable import Runnable
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.signer import LocalSigner, Signer
from raiden.utils.transfers import random_secret
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    Address,
    AddressMetadata,
    BlockNumber,
    BlockTimeout,
    InitiatorAddress,
    MonitoringServiceAddress,
    OneToNAddress,
    Optional,
    PaymentAmount,
    PaymentID,
    PrivateKey,
    Secret,
    SecretHash,
    SecretRegistryAddress,
    TargetAddress,
    TokenNetworkAddress,
    WithdrawAmount,
    typecheck,
)
from raiden.utils.upgrades import UpgradeManager
from raiden_contracts.constants import ChannelEvent
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)
StatusesDict = Dict[TargetAddress, Dict[PaymentID, "PaymentStatus"]]

PFS_UPDATE_CAPACITY_STATE_CHANGES = (
    ContractReceiveChannelDeposit,
    ReceiveUnlock,
    ReceiveWithdrawRequest,
    ReceiveWithdrawExpired,
    ReceiveTransferCancelRoute,
    ReceiveLockExpired,
    ReceiveTransferRefund,
    # State change | Reason why update is not needed
    # ActionInitInitiator | Update triggered by SendLockedTransfer
    # ActionInitMediator | Update triggered by SendLockedTransfer
    # ActionInitTarget | Update triggered by SendLockedTransfer
    # ActionTransferReroute | Update triggered by SendLockedTransfer
    # ActionChannelWithdraw | Upd. triggered by ReceiveWithdrawConfirmation/ReceiveWithdrawExpired
)
PFS_UPDATE_CAPACITY_EVENTS = (
    SendUnlock,
    SendLockedTransfer,
    SendWithdrawRequest,
    SendWithdrawExpired,
)

# Assume lower capacity for fees when in doubt, see
# https://raiden-network-specification.readthedocs.io/en/latest/pathfinding_service.html
#    #when-to-send-pfsfeeupdates
PFS_UPDATE_FEE_STATE_CHANGES = (
    ContractReceiveChannelDeposit,
    ReceiveWithdrawRequest,
    ReceiveWithdrawExpired,
)
PFS_UPDATE_FEE_EVENTS = (SendWithdrawRequest, SendWithdrawExpired)

assert not set(PFS_UPDATE_FEE_STATE_CHANGES) - set(
    PFS_UPDATE_CAPACITY_STATE_CHANGES
), "No fee updates without capacity updates possible"
assert not set(PFS_UPDATE_FEE_EVENTS) - set(
    PFS_UPDATE_CAPACITY_EVENTS
), "No fee updates without capacity updates possible"


def initiator_init(
    raiden: "RaidenService",
    transfer_identifier: PaymentID,
    transfer_amount: PaymentAmount,
    transfer_secret: Secret,
    transfer_secrethash: SecretHash,
    token_network_address: TokenNetworkAddress,
    target_address: TargetAddress,
    lock_timeout: BlockTimeout = None,
    route_states: List[RouteState] = None,
) -> Tuple[Optional[str], ActionInitInitiator]:
    transfer_state = TransferDescriptionWithSecretState(
        token_network_registry_address=raiden.default_registry.address,
        payment_identifier=transfer_identifier,
        amount=transfer_amount,
        token_network_address=token_network_address,
        initiator=InitiatorAddress(raiden.address),
        target=target_address,
        secret=transfer_secret,
        secrethash=transfer_secrethash,
        lock_timeout=lock_timeout,
    )

    error_msg = None
    if route_states is None:
        our_address_metadata = raiden.transport.address_metadata

        msg = "Transport is not initialized with raiden-service"
        assert our_address_metadata is not None, msg

        error_msg, route_states, feedback_token = routing.get_best_routes(
            chain_state=views.state_from_raiden(raiden),
            token_network_address=token_network_address,
            one_to_n_address=raiden.default_one_to_n_address,
            from_address=InitiatorAddress(raiden.address),
            to_address=target_address,
            amount=transfer_amount,
            previous_address=None,
            privkey=raiden.privkey,
            our_address_metadata=our_address_metadata,
            pfs_proxy=raiden.pfs_proxy,
        )

        # Only prepare feedback when token is available
        if feedback_token is not None:
            for route_state in route_states:
                raiden.route_to_feedback_token[tuple(route_state.route)] = feedback_token

    return error_msg, ActionInitInitiator(transfer_state, route_states)


def smart_contract_filters_from_node_state(
    chain_state: ChainState,
    secret_registry_address: SecretRegistryAddress,
    service_registry: Optional[ServiceRegistry],
) -> RaidenContractFilter:
    token_network_registries = chain_state.identifiers_to_tokennetworkregistries.values()
    token_networks = [tn for tnr in token_network_registries for tn in tnr.token_network_list]
    channels_of_token_network = {
        tn.address: set(tn.channelidentifiers_to_channels.keys())
        for tn in token_networks
        if tn.channelidentifiers_to_channels
    }

    return RaidenContractFilter(
        secret_registry_address=secret_registry_address,
        token_network_registry_addresses={tnr.address for tnr in token_network_registries},
        token_network_addresses={tn.address for tn in token_networks},
        channels_of_token_network=channels_of_token_network,
        ignore_secret_registry_until_channel_found=not channels_of_token_network,
        service_registry=service_registry,
    )


class PaymentStatus(NamedTuple):
    """Value type for RaidenService.targets_to_identifiers_to_statuses.

    Contains the necessary information to tell conflicting transfers from
    retries as well as the status of a transfer that is retried.
    """

    payment_identifier: PaymentID
    amount: PaymentAmount
    token_network_address: TokenNetworkAddress
    payment_done: AsyncResult
    lock_timeout: Optional[BlockTimeout]

    def matches(self, token_network_address: TokenNetworkAddress, amount: PaymentAmount) -> bool:
        return token_network_address == self.token_network_address and amount == self.amount


class SyncTimeout:
    """Helper to determine if the sync should halt or continue.

    The goal of this helper is to stop syncing before the block
    `current_confirmed_head` is pruned, otherwise JSON-RPC requests will start
    to fail.
    """

    def __init__(self, current_confirmed_head: BlockNumber, timeout: float) -> None:
        self.sync_start = time.monotonic()
        self.timeout = timeout
        self.current_confirmed_head = current_confirmed_head

    def time_elapsed(self) -> float:
        delta = time.monotonic() - self.sync_start
        return delta

    def should_continue(self, last_fetched_block: BlockNumber) -> bool:
        has_time = self.timeout >= self.time_elapsed()
        has_blocks_unsynched = self.current_confirmed_head > last_fetched_block

        return has_time and has_blocks_unsynched


class SynchronizationState(Enum):
    FULLY_SYNCED = "fully_synced"
    PARTIALLY_SYNCED = "partially_synced"


class RaidenService(Runnable):
    """A Raiden node."""

    def __init__(
        self,
        rpc_client: JSONRPCClient,
        proxy_manager: ProxyManager,
        query_start_block: BlockNumber,
        raiden_bundle: RaidenBundle,
        services_bundle: Optional[ServicesBundle],
        transport: MatrixTransport,
        raiden_event_handler: EventHandler,
        message_handler: MessageHandler,
        routing_mode: RoutingMode,
        config: RaidenConfig,
        api_server: Optional[APIServer] = None,
        pfs_proxy: PFSProxy = None,
    ) -> None:
        super().__init__()

        # check that the settlement timeout fits the limits of the contract
        settlement_timeout_min = raiden_bundle.token_network_registry.settlement_timeout_min(
            BLOCK_ID_LATEST
        )
        settlement_timeout_max = raiden_bundle.token_network_registry.settlement_timeout_max(
            BLOCK_ID_LATEST
        )
        invalid_settle_timeout = (
            config.settle_timeout < settlement_timeout_min
            or config.settle_timeout > settlement_timeout_max
            or config.settle_timeout < config.reveal_timeout * 2
        )
        if invalid_settle_timeout:
            contract = to_checksum_address(raiden_bundle.token_network_registry.address)
            raise InvalidSettleTimeout(
                (
                    f"Settlement timeout for Registry contract {contract} must "
                    f"be in range [{settlement_timeout_min}, {settlement_timeout_max}], "
                    f"is {config.settle_timeout}"
                )
            )

        self.targets_to_identifiers_to_statuses: StatusesDict = defaultdict(dict)

        one_to_n_address = None
        monitoring_service_address = None
        service_registry: Optional[ServiceRegistry] = None
        user_deposit: Optional[UserDeposit] = None

        if services_bundle:
            if services_bundle.one_to_n:
                one_to_n_address = services_bundle.one_to_n.address

            if services_bundle.monitoring_service:
                monitoring_service_address = services_bundle.monitoring_service.address

            service_registry = services_bundle.service_registry
            user_deposit = services_bundle.user_deposit

        self.rpc_client: JSONRPCClient = rpc_client
        self.proxy_manager: ProxyManager = proxy_manager
        self.default_registry: TokenNetworkRegistry = raiden_bundle.token_network_registry
        self.query_start_block = query_start_block
        self.default_services_bundle = services_bundle
        self.default_one_to_n_address: Optional[OneToNAddress] = one_to_n_address
        self.default_secret_registry: SecretRegistry = raiden_bundle.secret_registry
        self.default_service_registry = service_registry
        self.default_user_deposit: Optional[UserDeposit] = user_deposit
        self.default_msc_address: Optional[MonitoringServiceAddress] = monitoring_service_address
        self.routing_mode: RoutingMode = routing_mode
        self.config: RaidenConfig = config
        self.notifications: Dict = {}  # notifications are unique (and indexed) by id.

        self.signer: Signer = LocalSigner(self.rpc_client.privkey)
        self.address: Address = self.signer.address
        self.transport: MatrixTransport = transport

        self.alarm = AlarmTask(
            proxy_manager=proxy_manager, sleep_time=self.config.blockchain.query_interval
        )
        self.raiden_event_handler = raiden_event_handler
        self.message_handler = message_handler
        self.blockchain_events: Optional[BlockchainEvents] = None

        self.api_server: Optional[APIServer] = api_server
        self.raiden_api: Optional[RaidenAPI] = None
        self.rest_api: Optional[RestAPI] = None
        if api_server is not None:
            self.raiden_api = RaidenAPI(self)
            self.rest_api = api_server.rest_api

        self.stop_event = Event()
        self.stop_event.set()  # inits as stopped
        self.greenlets: List[Greenlet] = []

        self.last_log_time = time.monotonic()
        self.last_log_block = BlockNumber(0)

        self.contract_manager: ContractManager = ContractManager(config.contracts_path)
        self.wal: Optional[WriteAheadLog] = None
        self.db_lock: Optional[filelock.UnixFileLock] = None

        if pfs_proxy is None:
            assert config.pfs_config is not None, "must not be None"
            pfs_proxy = PFSProxy(config.pfs_config)
        self.pfs_proxy = pfs_proxy

        if self.config.database_path != ":memory:":
            database_dir = os.path.dirname(config.database_path)
            os.makedirs(database_dir, exist_ok=True)

            self.database_dir: Optional[str] = database_dir

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
            self.database_dir = None
            self.serialization_file = None
            self.db_lock = None

        self.payment_identifier_lock = gevent.lock.Semaphore()

        # A list is not hashable, so use tuple as key here
        self.route_to_feedback_token: Dict[Tuple[Address, ...], UUID] = {}

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

        # Counters used for state snapshotting
        self.state_change_qty_snapshot = 0
        self.state_change_qty = 0

    def start(self) -> None:
        """Start the node synchronously. Raises directly if anything went wrong on startup"""
        assert self.stop_event.ready(), f"Node already started. node:{self!r}"
        self.stop_event.clear()
        self.greenlets = []

        self.ready_to_process_events = False  # set to False because of restarts

        self._initialize_wal()
        self._synchronize_with_blockchain()

        chain_state = views.state_from_raiden(self)

        self._initialize_payment_statuses(chain_state)
        self._initialize_transactions_queues(chain_state)
        self._initialize_messages_queues(chain_state)
        self._initialize_channel_fees()
        self._initialize_monitoring_services_queue(chain_state)
        self._initialize_ready_to_process_events()

        # Start the side-effects:
        # - React to blockchain events
        # - React to incoming messages
        # - Send pending transactions
        # - Send pending message
        self.alarm.greenlet.link_exception(self.on_error)
        self.transport.greenlet.link_exception(self.on_error)
        if self.api_server is not None:
            self.api_server.greenlet.link_exception(self.on_error)
        self._start_transport()
        self._start_alarm_task()

        log.debug("Raiden Service started", node=to_checksum_address(self.address))
        super().start()

        self._set_rest_api_service_available()

    def _run(self, *args: Any, **kwargs: Any) -> None:  # pylint: disable=method-hidden
        """Busy-wait on long-lived subtasks/greenlets, re-raise if any error occurs"""
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
        """Stop the node gracefully. Raise if any stop-time error occurred on any subtask"""
        if self.stop_event.ready():  # not started
            return

        # Needs to come before any greenlets joining
        self.stop_event.set()

        # Filters must be uninstalled after the alarm task has stopped. Since
        # the events are polled by an alarm task callback, if the filters are
        # uninstalled before the alarm task is fully stopped the callback will
        # fail.
        #
        # We need a timeout to prevent an endless loop from trying to
        # contact the disconnected client
        if self.api_server is not None:
            self.api_server.stop()
            self.api_server.greenlet.join()

        self.alarm.stop()
        self.alarm.greenlet.join()

        self.transport.stop()
        self.transport.greenlet.join()

        assert (
            self.blockchain_events
        ), f"The blockchain_events has to be set by the start. node:{self!r}"
        self.blockchain_events.stop()

        # Close storage DB to release internal DB lock
        assert (
            self.wal
        ), f"The Service must have been started before it can be stopped. node:{self!r}"
        self.wal.storage.close()
        self.wal = None

        if self.db_lock is not None:
            self.db_lock.release()

        log.debug("Raiden Service stopped", node=to_checksum_address(self.address))

    def add_notification(
        self,
        notification: Notification,
        log_opts: Optional[Dict] = None,
        click_opts: Optional[Dict] = None,
    ) -> None:
        log_opts = log_opts or {}
        click_opts = click_opts or {}

        log.info(notification.summary, **log_opts)
        click.secho(notification.body, **click_opts)

        self.notifications[notification.id] = notification

    @property
    def confirmation_blocks(self) -> BlockTimeout:
        return self.config.blockchain.confirmation_blocks

    @property
    def privkey(self) -> PrivateKey:
        return self.rpc_client.privkey

    def add_pending_greenlet(self, greenlet: Greenlet) -> None:
        """Ensures an error on the passed greenlet crashes self/main greenlet."""

        def remove(_: Any) -> None:
            self.greenlets.remove(greenlet)

        self.greenlets.append(greenlet)
        greenlet.link_exception(self.on_error)
        greenlet.link_value(remove)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} node:{to_checksum_address(self.address)}>"

    def _start_transport(self) -> None:
        """Initialize the transport and related facilities.

        Note:
            The node has first to `_synchronize_with_blockchain` before
            starting the transport. This synchronization includes the on-chain
            channel state and is necessary to reject new messages for closed
            channels.
        """
        assert self.ready_to_process_events, f"Event processing disabled. node:{self!r}"
        msg = (
            "`self.blockchain_events` is `None`. "
            "Seems like `_synchronize_with_blockchain` wasn't called before `_start_transport`."
        )
        assert self.blockchain_events is not None, msg

        if self.default_service_registry is not None:
            populate_services_addresses(
                self.transport, self.default_service_registry, BLOCK_ID_LATEST
            )
        self.transport.start(raiden_service=self, prev_auth_data=None)

    def _make_initial_state(self) -> ChainState:
        # On first run Raiden needs to fetch all events for the payment
        # network, to reconstruct all token network graphs and find opened
        # channels
        #
        # The value `self.query_start_block` is an optimization, because
        # Raiden has to poll all events until the last confirmed block,
        # using the genesis block would result in fetchs for a few million
        # of unnecessary blocks. Instead of querying all these unnecessary
        # blocks, the configuration variable `query_start_block` is used to
        # start at the block which `TokenNetworkRegistry`  was deployed.
        last_log_block_number = self.query_start_block
        last_log_block_hash = self.rpc_client.blockhash_from_blocknumber(last_log_block_number)

        initial_state = ChainState(
            pseudo_random_generator=random.Random(),
            block_number=last_log_block_number,
            block_hash=last_log_block_hash,
            our_address=self.address,
            chain_id=self.rpc_client.chain_id,
        )
        token_network_registry_address = self.default_registry.address
        token_network_registry = TokenNetworkRegistryState(
            token_network_registry_address,
            [],  # empty list of token network states as it's the node's startup
        )
        initial_state.identifiers_to_tokennetworkregistries[
            token_network_registry_address
        ] = token_network_registry

        return initial_state

    def _initialize_wal(self) -> None:
        if self.database_dir is not None:
            try:
                assert (
                    self.db_lock is not None
                ), "If a database_dir is present, a lock for the database has to exist"
                self.db_lock.acquire(timeout=0)
                assert self.db_lock.is_locked, f"Database not locked. node:{self!r}"
            except (filelock.Timeout, AssertionError) as ex:
                raise RaidenUnrecoverableError(
                    "Could not aquire database lock. Maybe a Raiden node for this account "
                    f"({to_checksum_address(self.address)}) is already running?"
                ) from ex

        self.maybe_upgrade_db()

        storage = sqlite.SerializedSQLiteStorage(
            database_path=self.config.database_path, serializer=JSONSerializer()
        )
        storage.update_version()
        storage.log_run()

        try:
            initial_state = self._make_initial_state()
            (
                state_snapshot,
                state_change_start,
                state_change_qty_snapshot,
            ) = wal.restore_or_init_snapshot(
                storage=storage, node_address=self.address, initial_state=initial_state
            )

            state, state_change_qty_unapplied = wal.replay_state_changes(
                node_address=self.address,
                state=state_snapshot,
                state_change_range=Range(state_change_start, HIGH_STATECHANGE_ULID),
                storage=storage,
                transition_function=node.state_transition,  # type: ignore
            )
        except SerializationError:
            raise RaidenUnrecoverableError(
                "Could not restore state. "
                "It seems like the existing database is incompatible with "
                "the current version of Raiden. Consider using a stable "
                "version of the Raiden client."
            )

        if state_change_qty_snapshot == 0:
            print(
                "This is the first time Raiden is being used with this address. "
                "Processing all the events may take some time. Please wait ..."
            )

        self.state_change_qty_snapshot = state_change_qty_snapshot
        self.state_change_qty = state_change_qty_snapshot + state_change_qty_unapplied

        msg = "The state must be a ChainState instance."
        assert isinstance(state, ChainState), msg

        self.wal = WriteAheadLog(state, storage, node.state_transition)

        # The `Block` state change is dispatched only after all the events
        # for that given block have been processed, filters can be safely
        # installed starting from this position without losing events.
        last_log_block_number = views.block_number(self.wal.get_current_state())
        log.debug(
            "Querying blockchain from block",
            last_restored_block=last_log_block_number,
            node=to_checksum_address(self.address),
        )

        known_networks = views.get_token_network_registry_address(views.state_from_raiden(self))
        if known_networks and self.default_registry.address not in known_networks:
            configured_registry = to_checksum_address(self.default_registry.address)
            known_registries = lpex(known_networks)
            raise RuntimeError(
                f"Token network address mismatch.\n"
                f"Raiden is configured to use the smart contract "
                f"{configured_registry}, which conflicts with the current known "
                f"smart contracts {known_registries}"
            )

    def _log_sync_progress(
        self, polled_block_number: BlockNumber, target_block: BlockNumber
    ) -> None:
        """Print a message if there are many blocks to be fetched, or if the
        time in-between polls is high.
        """
        now = time.monotonic()
        blocks_until_target = target_block - polled_block_number
        polled_block_count = polled_block_number - self.last_log_block
        elapsed = now - self.last_log_time

        if blocks_until_target > 100 or elapsed > 15.0:
            log.info(
                "Synchronizing blockchain events",
                remaining_blocks_to_sync=blocks_until_target,
                blocks_per_second=polled_block_count / elapsed,
                to_block=target_block,
                elapsed=elapsed,
            )
            self.last_log_time = time.monotonic()
            self.last_log_block = polled_block_number

    def _synchronize_with_blockchain(self) -> None:
        """Prepares the alarm task callback and synchronize with the blockchain
        since the last run.

         Notes about setup order:
         - The filters must be polled after the node state has been primed,
           otherwise the state changes won't have effect.
         - The synchronization must be done before the transport is started, to
           reject messages for closed/settled channels.
        """
        msg = (
            f"Transport must not be started before the node has synchronized "
            f"with the blockchain, otherwise the node may accept transfers to a "
            f"closed channel. node:{self!r}"
        )
        assert not self.transport, msg
        assert self.wal, f"The database must have been initialized. node:{self!r}"

        chain_state = views.state_from_raiden(self)

        # The `Block` state change is dispatched only after all the events for
        # that given block have been processed, filters can be safely installed
        # starting from this position without missing events.
        last_block_number = views.block_number(chain_state)

        event_filter = smart_contract_filters_from_node_state(
            chain_state,
            self.default_secret_registry.address,
            self.default_service_registry,
        )

        log.debug("initial filter", event_filter=event_filter, node=self.address)
        blockchain_events = BlockchainEvents(
            web3=self.rpc_client.web3,
            chain_id=chain_state.chain_id,
            contract_manager=self.contract_manager,
            last_fetched_block=last_block_number,
            event_filter=event_filter,
            block_batch_size_config=self.config.blockchain.block_batch_size_config,
            node_address=self.address,
        )
        blockchain_events.register_listener(self._blockchain_event_listener)

        self.last_log_block = last_block_number
        self.last_log_time = time.monotonic()

        # `blockchain_events` is a requirement for
        # `_best_effort_synchronize_with_confirmed_head`, so it must be set
        # before calling it
        self.blockchain_events = blockchain_events

        synchronization_state = SynchronizationState.PARTIALLY_SYNCED
        while synchronization_state is SynchronizationState.PARTIALLY_SYNCED:
            latest_block = self.rpc_client.get_block(block_identifier=BLOCK_ID_LATEST)
            synchronization_state = self._best_effort_synchronize(latest_block)

        self.alarm.register_callback(self._best_effort_synchronize)

    def _blockchain_event_listener(self, events: List[DecodedEvent]) -> None:
        if not self.transport.started:
            return
        for event in events:
            args = event.event_data["args"]
            if event.event_data["event"] == ChannelEvent.OPENED:
                other = (
                    args["participant1"]
                    if args["participant1"] != self.address
                    else args["participant2"]
                )
                self.transport.health_check_web_rtc(other)

    def _start_alarm_task(self) -> None:
        """Start the alarm task.

        Note:
            The alarm task must be started only when processing events is
            allowed, otherwise side-effects of blockchain events will be
            ignored.
        """
        assert self.ready_to_process_events, f"Event processing disabled. node:{self!r}"
        self.alarm.start()

    def _set_rest_api_service_available(self) -> None:
        if self.raiden_api:
            assert self.rest_api, "api enabled in config but self.rest_api not initialized"
            self.rest_api.raiden_api = self.raiden_api
            print("Synchronization complete, REST API services now available.")

    def _initialize_ready_to_process_events(self) -> None:
        """Mark the node as ready to start processing raiden events that may
        send messages or transactions.

        This flag /must/ be set to true before the both  transport and the
        alarm are started.
        """
        msg = (
            f"The transport must not be initialized before the "
            f"`ready_to_process_events` flag is set, since this is a requirement "
            f"for the alarm task and the alarm task should be started before the "
            f"transport to avoid race conditions. node:{self!r}"
        )
        assert not self.transport, msg
        msg = (
            f"Alarm task must not be started before the "
            f"`ready_to_process_events` flag is set, otherwise events may be "
            f"missed. node:{self!r}"
        )
        assert not self.alarm, msg

        self.ready_to_process_events = True

    def get_block_number(self) -> BlockNumber:
        assert self.wal, f"WAL object not yet initialized. node:{self!r}"
        return views.block_number(self.wal.get_current_state())

    def on_messages(self, messages: List[Message]) -> None:
        self.message_handler.on_messages(self, messages)

    def handle_and_track_state_changes(self, state_changes: List[StateChange]) -> None:
        """Dispatch the state change and does not handle the exceptions.

        When the method is used the exceptions are tracked and re-raised in the
        raiden service thread.
        """
        if len(state_changes) == 0:
            return

        # It's important to /not/ block here, because this function can
        # be called from the alarm task greenlet, which should not
        # starve. This was a problem when the node decided to send a new
        # transaction, since the proxies block until the transaction is
        # mined and confirmed (e.g. the settle window is over and the
        # node sends the settle transaction).
        for greenlet in self.handle_state_changes(state_changes):
            self.add_pending_greenlet(greenlet)

    def handle_state_changes(self, state_changes: List[StateChange]) -> List[Greenlet]:
        """Dispatch the state change and return the processing threads.

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

        raiden_events = []

        with self.wal.process_state_change_atomically() as dispatcher:
            for state_change in state_changes:
                events = dispatcher.dispatch(state_change)
                raiden_events.extend(events)

        return self._trigger_state_change_effects(
            new_state=views.state_from_raiden(self),
            state_changes=state_changes,
            events=raiden_events,
        )

    def _trigger_state_change_effects(
        self,
        new_state: ChainState,
        state_changes: List[StateChange],
        events: List[Event],
    ) -> List[Greenlet]:
        """Trigger effects that are based on processed state changes.

        Examples are MS/PFS updates, transport communication channel updates
        and presence checks.
        """
        # For safety of the mediation the monitoring service must be updated
        # before the balance proof is sent. Otherwise a timing attack would be
        # possible, where an attacker would mediate a transfer through a node,
        # and try to DoS it, with the expectation that the victim would
        # forward the payment, but wouldn't be able to send a transaction to
        # the blockchain nor update a MS.

        # Since several state_changes in one batch of state_changes can trigger
        # the same PFSCapacityUpdate or MonitoringUpdate we want to iterate over
        # all state changes to produce and send only unique messages. Assumption is
        # that the latest related state_change defines the correct messages.
        # Goal is to reduce messages.
        monitoring_updates: Dict[CanonicalIdentifier, BalanceProofStateChange] = {}
        pfs_fee_updates: Set[CanonicalIdentifier] = set()
        pfs_capacity_updates: Set[CanonicalIdentifier] = set()

        for state_change in state_changes:
            if self.config.services.monitoring_enabled and isinstance(
                state_change, BalanceProofStateChange
            ):
                monitoring_updates[state_change.balance_proof.canonical_identifier] = state_change

            if isinstance(state_change, PFS_UPDATE_CAPACITY_STATE_CHANGES):
                if isinstance(state_change, BalanceProofStateChange):
                    canonical_identifier = state_change.balance_proof.canonical_identifier
                else:
                    canonical_identifier = state_change.canonical_identifier

                if isinstance(state_change, PFS_UPDATE_FEE_STATE_CHANGES):
                    pfs_fee_updates.add(canonical_identifier)
                else:
                    pfs_capacity_updates.add(canonical_identifier)
            if isinstance(state_change, Block):
                self.transport.expire_services_addresses(
                    self.rpc_client.get_block(state_change.block_hash)["timestamp"],
                    state_change.block_number,
                )

        for event in events:
            if isinstance(event, PFS_UPDATE_FEE_EVENTS):
                pfs_fee_updates.add(event.canonical_identifier)
            elif isinstance(event, PFS_UPDATE_CAPACITY_EVENTS):
                pfs_capacity_updates.add(event.canonical_identifier)

        for monitoring_update in monitoring_updates.values():
            update_monitoring_service_from_balance_proof(
                raiden=self,
                chain_state=new_state,
                new_balance_proof=monitoring_update.balance_proof,
                non_closing_participant=self.address,
            )

        for canonical_identifier in pfs_capacity_updates:
            send_pfs_update(raiden=self, canonical_identifier=canonical_identifier)

        for canonical_identifier in pfs_fee_updates:
            send_pfs_update(
                raiden=self, canonical_identifier=canonical_identifier, update_fee_schedule=True
            )

        log.debug(
            "Raiden events",
            node=to_checksum_address(self.address),
            raiden_events=[redact_secret(DictSerializer.serialize(event)) for event in events],
        )

        self.state_change_qty += len(state_changes)
        self._maybe_snapshot()

        if self.ready_to_process_events:
            return self.async_handle_events(chain_state=new_state, raiden_events=events)
        else:
            return []

    def _maybe_snapshot(self) -> None:
        if self.state_change_qty > self.state_change_qty_snapshot + SNAPSHOT_STATE_CHANGES_COUNT:
            assert self.wal, "WAL must be set."

            log.debug("Storing snapshot")
            self.wal.snapshot(self.state_change_qty)
            self.state_change_qty_snapshot = self.state_change_qty

    def async_handle_events(
        self, chain_state: ChainState, raiden_events: List[RaidenEvent]
    ) -> List[Greenlet]:
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

            This is spawning a new greenlet for /each/ transaction. It's
            therefore /required/ that there is *NO* order among these.
        """
        typecheck(chain_state, ChainState)

        event_wrapper = EventWrapper(raiden_events)
        parsed_events = event_wrapper.wrap_events()

        fast_events = []
        greenlets: List[Greenlet] = []

        # These events are slow to process, and they will add extra delay to the protocol messages.
        # To avoid unnecessary delays and weird edge cases, every event that can lead to a blocking
        # operation is handled in a separated thread.
        #
        # - ContractSend* events will send transactions that can take multiple minutes to be
        #   processed, since that will wait for the transaction to be mined and confirmed.
        # - SecretSecretRequest events may take a long time if a resolver is used, which can be as
        #   high as the lock expiration (couple of minutes).
        # - Payment related events may block on the PFS. (see `PFSFeedbackEventHandler`)
        blocking_events = (
            EventRouteFailed,
            EventPaymentSentSuccess,
            SendSecretRequest,
            ContractSendEvent,
            RequestMetadata,
        )

        for event in parsed_events:
            if isinstance(event, blocking_events):
                greenlets.append(
                    spawn_named(
                        "rs-handle_blocking_events", self._handle_events, chain_state, [event]
                    )
                )
            else:
                fast_events.append(event)

        if fast_events:
            greenlets.append(
                spawn_named("rs-handle_events", self._handle_events, chain_state, fast_events)
            )

        return greenlets

    def _handle_events(self, chain_state: ChainState, raiden_events: List[RaidenEvent]) -> None:
        try:
            self.raiden_event_handler.on_raiden_events(
                raiden=self, chain_state=chain_state, events=raiden_events
            )
        except RaidenRecoverableError as e:
            log.info(str(e))
        except InvalidDBData:
            raise
        except (RaidenUnrecoverableError, BrokenPreconditionError) as e:
            log_unrecoverable = (
                self.config.environment_type == Environment.PRODUCTION
                and not self.config.unrecoverable_error_should_crash
            )
            if log_unrecoverable:
                log.error(str(e))
            else:
                raise

    def _best_effort_synchronize(self, latest_block: BlockData) -> SynchronizationState:
        """Called with the current latest block, tries to synchronize with the
        *confirmed* head of the chain in a best effort manner, it is not
        guaranteed to succeed in a single call since `latest_block` may become
        pruned.

        Note:
            This should be called only once per block, otherwise there will be
            duplicated `Block` state changes in the log.
        """

        latest_block_number = latest_block["number"]

        # Handle testing with private chains. The block number can be
        # smaller than confirmation_blocks
        current_confirmed_head = BlockNumber(
            max(GENESIS_BLOCK_NUMBER, latest_block_number - self.confirmation_blocks)
        )

        return self._best_effort_synchronize_with_confirmed_head(
            current_confirmed_head, self.config.blockchain.timeout_before_block_pruned
        )

    def _best_effort_synchronize_with_confirmed_head(
        self, current_confirmed_head: BlockNumber, timeout: float
    ) -> SynchronizationState:
        """Tries to synchronize with the blockchain events up to
        `current_confirmed_head`. This may stop before being fully synchronized
        if the number of `current_confirmed_head` is close to be pruned.

        Multiple queries may be necessary on restarts, because the node may
        have been offline for an extend period of time. During normal
        operation, this must not happen, because in this case the node may have
        missed important events, like a channel close, while the transport
        layer is running, this can lead to loss of funds.

        It is very important for `current_confirmed_head` to be a confirmed
        block that has not been pruned. Unconfirmed blocks are a problem
        because of reorgs, since some operations performed based on the events
        are irreversible, namely sending a balance proof after a channel
        deposit, once a node accepts a deposit, these tokens can be used to do
        mediated transfers, and if a reorg removes the deposit tokens could be
        lost. Using older blocks are a problem because of data availability
        problems, in some cases it is necessary to query the blockchain to
        fetch data which is not available in an event, the original event block
        is used, however that block may have been pruned if the synchronization
        is considerably lagging behind (which happens after long restarts), so
        a new block number is necessary to be used as a fallback, a `latest`
        is not a valid option because of the reorgs.

        This function takes care of fetching blocks in batches and confirming
        their result. This is important to keep memory usage low and to speed
        up restarts. Memory usage can get a hit if the node is asleep for a
        long period of time, since all the missing confirmed blocks have to be
        fetched before the node is in a working state. Restarts get a hit if
        the node is closed while it was synchronizing, without regularly saving
        that work, if the node is killed while synchronizing, it only gets
        gradually slower.
        """
        msg = (
            f"The blockchain event handler has to be instantiated before the "
            f"alarm task is started. node:{self!r}"
        )
        assert self.blockchain_events, msg

        state_changes = []
        raiden_events = []

        guard = SyncTimeout(current_confirmed_head, timeout)
        while guard.should_continue(self.blockchain_events.last_fetched_block):
            poll_result = self.blockchain_events.fetch_logs_in_batch(current_confirmed_head)
            if poll_result is None:
                # No blocks could be fetched (due to timeout), retry
                continue

            assert self.wal, "raiden.wal not set"
            with self.wal.process_state_change_atomically() as dispatcher:
                for event in poll_result.events:
                    # Important: `blockchainevent_to_statechange` has to be called
                    # with the block of the current confirmed head! An unconfirmed
                    # block could lead to the wrong state being dispatched because
                    # of reorgs, and older blocks are not sufficient to fix
                    # problems with pruning, the `SyncTimeout` is used to ensure
                    # the `current_confirmed_head` stays valid.
                    maybe_state_change = blockchainevent_to_statechange(
                        raiden_config=self.config,
                        raiden_storage=self.wal.storage,  # FXIME: use more recent
                        chain_state=dispatcher.latest_state(),
                        event=event,
                    )
                    if maybe_state_change is not None:
                        events = dispatcher.dispatch(maybe_state_change)

                        state_changes.append(maybe_state_change)
                        raiden_events.extend(events)

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
                # The approach used below is to dispatch the Block and the
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
                # processed, the block hash used as the triggering block for the
                # deposit will be off-by-one, and it will point to the block
                # immediately before the channel existed. This breaks a proxy
                # precondition which crashes the client.
                block_state_change = Block(
                    block_number=poll_result.polled_block_number,
                    gas_limit=poll_result.polled_block_gas_limit,
                    block_hash=poll_result.polled_block_hash,
                )
                events = dispatcher.dispatch(block_state_change)
                state_changes.append(block_state_change)
                raiden_events.extend(events)

            self._log_sync_progress(poll_result.polled_block_number, current_confirmed_head)

        log.debug(
            "State changes",
            node=to_checksum_address(self.address),
            state_changes=[
                redact_secret(DictSerializer.serialize(state_change))
                for state_change in state_changes
            ],
        )

        event_greenlets = self._trigger_state_change_effects(
            new_state=views.state_from_raiden(self),
            state_changes=state_changes,
            events=raiden_events,
        )
        for greenlet in event_greenlets:
            self.add_pending_greenlet(greenlet)

        current_synched_block_number = self.get_block_number()

        log.debug(
            "Synchronized to a new confirmed block",
            sync_elapsed=guard.time_elapsed(),
            block_number=current_synched_block_number,
        )

        msg = "current_synched_block_number is larger than current_confirmed_head"
        assert current_synched_block_number <= current_confirmed_head, msg

        if current_synched_block_number < current_confirmed_head:
            return SynchronizationState.PARTIALLY_SYNCED

        return SynchronizationState.FULLY_SYNCED

    def _initialize_transactions_queues(self, chain_state: ChainState) -> None:
        """Initialize the pending transaction queue from the previous run.

        Note:
            This will only send the transactions which don't have their
            side-effects applied. Transactions which another node may have sent
            already will be detected by the alarm task's first run and cleared
            from the queue (e.g. A monitoring service update transfer).
        """
        msg = (
            f"Initializing the transaction queue requires the state to be restored. node:{self!r}"
        )
        assert self.wal, msg
        msg = (
            f"Initializing the transaction queue must be done after the "
            f"blockchain has be synched. This removes invalidated transactions from "
            f"the queue. node:{self!r}"
        )
        assert self.blockchain_events, msg

        pending_transactions = cast(List[RaidenEvent], views.get_pending_transactions(chain_state))

        log.debug(
            "Initializing transaction queues",
            num_pending_transactions=len(pending_transactions),
            node=to_checksum_address(self.address),
        )

        transaction_greenlets = self.async_handle_events(
            chain_state=chain_state, raiden_events=pending_transactions
        )
        for greeenlet in transaction_greenlets:
            self.add_pending_greenlet(greeenlet)

    def _initialize_payment_statuses(self, chain_state: ChainState) -> None:
        """Re-initialize targets_to_identifiers_to_statuses.

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
                    lock_timeout=initiator.transfer_description.lock_timeout,
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
        msg = f"Node must be synchronized with the blockchain. node:{self!r}"
        assert self.blockchain_events, msg

        events_queues = views.get_all_messagequeues(chain_state)

        log.debug(
            "Initializing message queues",
            queues_identifiers=list(events_queues.keys()),
            node=to_checksum_address(self.address),
        )

        all_messages: List[MessagesQueue] = []
        for queue_identifier, event_queue in events_queues.items():

            queue_messages: List[Tuple[Message, Optional[AddressMetadata]]] = []
            for event in event_queue:
                message = message_from_sendevent(event)
                self.sign(message)
                # FIXME: this will load the recipient's metadata from the persisted
                #  state. If the recipient roamed during the offline time of our node,
                #  the message will never reach the recipient,
                #  especially since we don't have a WebRTC connection with the recipient at
                #  startup.
                #  Depending on the time our node is offline, roaming of the recipient
                #  can become more likely.
                queue_messages.append((message, event.recipient_metadata))

            all_messages.append(MessagesQueue(queue_identifier, queue_messages))

        self.transport.send_async(all_messages)

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
            f"Transport was started before the monitoring service queue was updated. "
            f"This can lead to safety issue. node:{self!r}"
        )
        assert not self.transport, msg

        msg = f"The node state was not yet recovered, cant read balance proofs. node:{self!r}"
        assert self.wal, msg

        # Fetch all balance proofs from the chain_state
        current_balance_proofs: List[BalanceProofSignedState] = []
        for tn_registry in chain_state.identifiers_to_tokennetworkregistries.values():
            for tn in tn_registry.tokennetworkaddresses_to_tokennetworks.values():
                for channel in tn.channelidentifiers_to_channels.values():
                    balance_proof = channel.partner_state.balance_proof
                    if not balance_proof:
                        continue
                    assert isinstance(balance_proof, BalanceProofSignedState), MYPY_ANNOTATION
                    current_balance_proofs.append(balance_proof)

        log.debug(
            "Initializing monitoring services",
            num_of_balance_proofs=len(current_balance_proofs),
            node=to_checksum_address(self.address),
        )

        for balance_proof in current_balance_proofs:
            update_monitoring_service_from_balance_proof(
                self,
                chain_state=chain_state,
                new_balance_proof=balance_proof,
                non_closing_participant=self.address,
            )

    def _initialize_channel_fees(self) -> None:
        """Initializes the fees of all open channels to the latest set values.

        This includes a recalculation of the dynamic rebalancing fees.
        """
        chain_state = views.state_from_raiden(self)
        fee_config = self.config.mediation_fees
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
                flat_fee = fee_config.get_flat_fee(channel.token_address)
                proportional_fee = fee_config.get_proportional_fee(channel.token_address)
                proportional_imbalance_fee = fee_config.get_proportional_imbalance_fee(
                    channel.token_address
                )
                log.info(
                    "Updating channel fees",
                    channel=channel.canonical_identifier,
                    cap_mediation_fees=fee_config.cap_meditation_fees,
                    flat_fee=flat_fee,
                    proportional_fee=proportional_fee,
                    proportional_imbalance_fee=proportional_imbalance_fee,
                )
                imbalance_penalty = calculate_imbalance_fees(
                    channel_capacity=get_capacity(channel),
                    proportional_imbalance_fee=proportional_imbalance_fee,
                )
                channel.fee_schedule = FeeScheduleState(
                    cap_fees=fee_config.cap_meditation_fees,
                    flat=flat_fee,
                    proportional=proportional_fee,
                    imbalance_penalty=imbalance_penalty,
                )
                send_pfs_update(
                    raiden=self,
                    canonical_identifier=channel.canonical_identifier,
                    update_fee_schedule=True,
                )

    def sign(self, message: Message) -> None:
        """Sign message inplace."""
        if not isinstance(message, SignedMessage):
            raise ValueError("{} is not signable.".format(repr(message)))

        message.sign(self.signer)

    def mediated_transfer_async(
        self,
        token_network_address: TokenNetworkAddress,
        amount: PaymentAmount,
        target: TargetAddress,
        identifier: PaymentID,
        secret: Secret = None,
        secrethash: SecretHash = None,
        lock_timeout: BlockTimeout = None,
        route_states: List[RouteState] = None,
    ) -> PaymentStatus:
        """Transfer `amount` between this node and `target`.

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

        if secrethash is None:
            secrethash = sha256_secrethash(secret)
        elif secret != ABSENT_SECRET:
            if secrethash != sha256_secrethash(secret):
                raise InvalidSecretHash("provided secret and secret_hash do not match.")
            if len(secret) != SECRET_LENGTH:
                raise InvalidSecret("secret of invalid length.")

        log.debug(
            "Mediated transfer",
            node=to_checksum_address(self.address),
            target=to_checksum_address(target),
            amount=amount,
            identifier=identifier,
            token_network_address=to_checksum_address(token_network_address),
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
            secrethash=secrethash, block_identifier=BLOCK_ID_LATEST
        )
        if secret_registered:
            raise RaidenUnrecoverableError(
                f"Attempted to initiate a locked transfer with secrethash {to_hex(secrethash)}."
                f" That secret is already registered onchain."
            )

        # Checks if there is a payment in flight with the same payment_id and
        # target. If there is such a payment and the details match, instead of
        # starting a new payment this will give the caller the existing
        # details. This prevents Raiden from having concurrently identical
        # payments, which would likely mean paying more than once for the same
        # thing.
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
                lock_timeout=lock_timeout,
            )
            self.targets_to_identifiers_to_statuses[target][identifier] = payment_status

        error_msg, init_initiator_statechange = initiator_init(
            raiden=self,
            transfer_identifier=identifier,
            transfer_amount=amount,
            transfer_secret=secret,
            transfer_secrethash=secrethash,
            token_network_address=token_network_address,
            target_address=target,
            lock_timeout=lock_timeout,
            route_states=route_states,
        )

        # FIXME: Dispatch the state change even if there are no routes to
        # create the WAL entry.
        if error_msg is None:
            self.handle_and_track_state_changes([init_initiator_statechange])
        else:
            failed = EventPaymentSentFailed(
                token_network_registry_address=self.default_registry.address,
                token_network_address=token_network_address,
                identifier=identifier,
                target=target,
                reason=error_msg,
            )
            payment_status.payment_done.set(failed)

        return payment_status

    def withdraw(
        self,
        canonical_identifier: CanonicalIdentifier,
        total_withdraw: WithdrawAmount,
        recipient_metadata: AddressMetadata = None,
    ) -> None:

        init_withdraw = ActionChannelWithdraw(
            canonical_identifier=canonical_identifier,
            total_withdraw=total_withdraw,
            recipient_metadata=recipient_metadata,
        )

        self.handle_and_track_state_changes([init_withdraw])

    def set_channel_reveal_timeout(
        self, canonical_identifier: CanonicalIdentifier, reveal_timeout: BlockTimeout
    ) -> None:
        action_set_channel_reveal_timeout = ActionChannelSetRevealTimeout(
            canonical_identifier=canonical_identifier, reveal_timeout=reveal_timeout
        )

        self.handle_and_track_state_changes([action_set_channel_reveal_timeout])

    def maybe_upgrade_db(self) -> None:
        manager = UpgradeManager(
            db_filename=self.config.database_path, raiden=self, web3=self.rpc_client.web3
        )
        manager.run()
