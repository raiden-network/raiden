# pylint: disable=too-many-lines
import os
import random
from collections import defaultdict
from typing import Dict, List, NamedTuple, Union

import filelock
import gevent
import structlog
from eth_utils import is_binary_address
from gevent import Greenlet
from gevent.event import AsyncResult, Event

from raiden import constants, routing
from raiden.blockchain.events import BlockchainEvents
from raiden.blockchain_events_handler import on_blockchain_event
from raiden.connection_manager import ConnectionManager
from raiden.constants import (
    EMPTY_SECRET,
    GENESIS_BLOCK_NUMBER,
    SECRET_LENGTH,
    SNAPSHOT_STATE_CHANGES_COUNT,
    Environment,
)
from raiden.exceptions import (
    InvalidAddress,
    InvalidDBData,
    InvalidSecret,
    InvalidSecretHash,
    PaymentConflict,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
)
from raiden.messages import (
    LockedTransfer,
    Message,
    RequestMonitoring,
    SignedMessage,
    UpdatePFS,
    message_from_sendevent,
)
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.settings import MEDIATION_FEE, MONITORING_MIN_CAPACITY, MONITORING_REWARD
from raiden.storage import serialize, sqlite, wal
from raiden.tasks import AlarmTask
from raiden.transfer import channel, node, views
from raiden.transfer.architecture import Event as RaidenEvent, StateChange
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
from raiden.transfer.state import (
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    ChainState,
    InitiatorTask,
    PaymentNetworkState,
    RouteState,
)
from raiden.transfer.state_change import (
    ActionChangeNodeNetworkState,
    ActionInitChain,
    Block,
    ContractReceiveNewPaymentNetwork,
)
from raiden.utils import create_default_identifier, lpex, pex, random_secret, sha3, to_rdn
from raiden.utils.runnable import Runnable
from raiden.utils.signer import LocalSigner, Signer
from raiden.utils.typing import (
    Address,
    BlockHash,
    BlockNumber,
    FeeAmount,
    InitiatorAddress,
    Optional,
    PaymentAmount,
    PaymentID,
    Secret,
    SecretHash,
    TargetAddress,
    TokenNetworkAddress,
    TokenNetworkID,
)
from raiden.utils.upgrades import UpgradeManager
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name
StatusesDict = Dict[TargetAddress, Dict[PaymentID, "PaymentStatus"]]
ConnectionManagerDict = Dict[TokenNetworkID, ConnectionManager]


def _redact_secret(data: Union[Dict, List],) -> Union[Dict, List]:
    """ Modify `data` in-place and replace keys named `secret`. """

    if isinstance(data, dict):
        stack = [data]
    else:
        stack = []

    while stack:
        current = stack.pop()

        if "secret" in current:
            current["secret"] = "<redacted>"
        else:
            stack.extend(value for value in current.values() if isinstance(value, dict))

    return data


def initiator_init(
    raiden: "RaidenService",
    transfer_identifier: PaymentID,
    transfer_amount: PaymentAmount,
    transfer_secret: Secret,
    transfer_secrethash: SecretHash,
    transfer_fee: FeeAmount,
    token_network_identifier: TokenNetworkID,
    target_address: TargetAddress,
) -> ActionInitInitiator:
    assert transfer_secret != constants.EMPTY_HASH, f"Empty secret node:{raiden!r}"

    transfer_state = TransferDescriptionWithSecretState(
        payment_network_identifier=raiden.default_registry.address,
        payment_identifier=transfer_identifier,
        amount=transfer_amount,
        allocated_fee=transfer_fee,
        token_network_identifier=token_network_identifier,
        initiator=InitiatorAddress(raiden.address),
        target=target_address,
        secret=transfer_secret,
        secrethash=transfer_secrethash,
    )
    previous_address = None
    routes, _ = routing.get_best_routes(
        chain_state=views.state_from_raiden(raiden),
        token_network_id=token_network_identifier,
        one_to_n_address=raiden.default_one_to_n_address,
        from_address=InitiatorAddress(raiden.address),
        to_address=target_address,
        amount=transfer_amount,
        previous_address=previous_address,
        config=raiden.config,
        privkey=raiden.privkey,
    )
    return ActionInitInitiator(transfer_state, routes)


def mediator_init(raiden, transfer: LockedTransfer) -> ActionInitMediator:
    from_transfer = lockedtransfersigned_from_message(transfer)
    # Feedback token not used here, will be removed with source routing
    routes, _ = routing.get_best_routes(
        chain_state=views.state_from_raiden(raiden),
        token_network_id=TokenNetworkID(from_transfer.balance_proof.token_network_identifier),
        one_to_n_address=raiden.default_one_to_n_address,
        from_address=raiden.address,
        to_address=from_transfer.target,
        amount=PaymentAmount(from_transfer.lock.amount),  # FIXME: mypy; deprecated through #3863
        previous_address=transfer.sender,
        config=raiden.config,
        privkey=raiden.privkey,
    )
    from_route = RouteState(transfer.sender, from_transfer.balance_proof.channel_identifier)
    return ActionInitMediator(routes, from_route, from_transfer)


def target_init(transfer: LockedTransfer) -> ActionInitTarget:
    from_transfer = lockedtransfersigned_from_message(transfer)
    from_route = RouteState(transfer.sender, from_transfer.balance_proof.channel_identifier)
    return ActionInitTarget(from_route, from_transfer)


class PaymentStatus(NamedTuple):
    """Value type for RaidenService.targets_to_identifiers_to_statuses.

    Contains the necessary information to tell conflicting transfers from
    retries as well as the status of a transfer that is retried.
    """

    payment_identifier: PaymentID
    amount: PaymentAmount
    token_network_identifier: TokenNetworkID
    payment_done: AsyncResult

    def matches(self, token_network_identifier: TokenNetworkID, amount: PaymentAmount):
        return token_network_identifier == self.token_network_identifier and amount == self.amount


def update_services_from_balance_proof(
    raiden: "RaidenService",
    chain_state: "ChainState",
    balance_proof: Union[BalanceProofSignedState, BalanceProofUnsignedState],
) -> None:
    update_path_finding_service_from_balance_proof(
        raiden=raiden, chain_state=chain_state, new_balance_proof=balance_proof
    )
    if isinstance(balance_proof, BalanceProofSignedState):
        update_monitoring_service_from_balance_proof(
            raiden=raiden, chain_state=chain_state, new_balance_proof=balance_proof
        )


def update_path_finding_service_from_balance_proof(
    raiden: "RaidenService",
    chain_state: "ChainState",
    new_balance_proof: Union[BalanceProofSignedState, BalanceProofUnsignedState],
) -> None:
    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state, canonical_identifier=new_balance_proof.canonical_identifier
    )
    network_address = new_balance_proof.canonical_identifier.token_network_address
    error_msg = (
        f"tried to send a balance proof in non-existant channel "
        f"token_network_address: {pex(network_address)} "
    )
    assert channel_state is not None, error_msg
    if isinstance(new_balance_proof, BalanceProofSignedState):
        assert channel_state.partner_state.balance_proof == new_balance_proof
    else:  # BalanceProofUnsignedState
        assert channel_state.our_state.balance_proof == new_balance_proof

    msg = UpdatePFS.from_channel_state(channel_state)
    msg.sign(raiden.signer)
    raiden.transport.send_global(constants.PATH_FINDING_BROADCASTING_ROOM, msg)
    log.debug("Sent a PFS Update", message=msg, balance_proof=new_balance_proof)


def update_monitoring_service_from_balance_proof(
    raiden: "RaidenService", chain_state: "ChainState", new_balance_proof: BalanceProofSignedState
) -> None:
    if raiden.config["services"]["monitoring_enabled"] is False:
        return

    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state, canonical_identifier=new_balance_proof.canonical_identifier
    )

    msg = (
        f"Failed to update monitoring service due to inability to find "
        f"channel: {new_balance_proof.channel_identifier} "
        f"token_network_address: {pex(new_balance_proof.token_network_identifier)}."
    )
    assert channel_state, msg

    balance = channel.get_balance(
        sender=channel_state.our_state, receiver=channel_state.partner_state
    )

    if balance < MONITORING_MIN_CAPACITY:
        log.warn(
            f"Skipping update to Monitoring service. "
            f"Available balance of {balance} is less than configured "
            f"minimum capacity of {MONITORING_MIN_CAPACITY}"
        )
        return

    rei_balance = raiden.user_deposit.effective_balance(raiden.address, "latest")
    if rei_balance < MONITORING_REWARD:
        rdn_balance = to_rdn(rei_balance)
        rdn_reward = to_rdn(MONITORING_REWARD)
        log.warn(
            f"Skipping update to Monitoring service. "
            f"Your deposit balance {rdn_balance} is less than "
            f"the required monitoring service reward of {rdn_reward}"
        )
        return

    log.info(
        "Received new balance proof, creating message for Monitoring Service.",
        balance_proof=new_balance_proof,
    )

    monitoring_message = RequestMonitoring.from_balance_proof_signed_state(
        new_balance_proof, MONITORING_REWARD
    )
    monitoring_message.sign(raiden.signer)
    raiden.transport.send_global(constants.MONITORING_BROADCASTING_ROOM, monitoring_message)


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
        transport,
        raiden_event_handler,
        message_handler,
        config,
        discovery=None,
        user_deposit=None,
    ):
        super().__init__()
        self.tokennetworkids_to_connectionmanagers: ConnectionManagerDict = dict()
        self.targets_to_identifiers_to_statuses: StatusesDict = defaultdict(dict)

        self.chain: BlockChainService = chain
        self.default_registry = default_registry
        self.query_start_block = query_start_block
        self.default_one_to_n_address = default_one_to_n_address
        self.default_secret_registry = default_secret_registry
        self.default_service_registry = default_service_registry
        self.config = config

        self.signer: Signer = LocalSigner(self.chain.client.privkey)
        self.address = self.signer.address
        self.discovery = discovery
        self.transport = transport

        self.user_deposit = user_deposit

        self.blockchain_events = BlockchainEvents()
        self.alarm = AlarmTask(chain)
        self.raiden_event_handler = raiden_event_handler
        self.message_handler = message_handler

        self.stop_event = Event()
        self.stop_event.set()  # inits as stopped
        self.greenlets: List[Greenlet] = list()

        self.snapshot_group = 0

        self.contract_manager = ContractManager(config["contracts_path"])
        self.database_path = config["database_path"]
        self.wal = None
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

    def start(self):
        """ Start the node synchronously. Raises directly if anything went wrong on startup """
        assert self.stop_event.ready(), f"Node already started. node:{self!r}"
        self.stop_event.clear()
        self.greenlets = list()

        self.ready_to_process_events = False  # set to False because of restarts

        if self.database_dir is not None:
            self.db_lock.acquire(timeout=0)
            assert self.db_lock.is_locked, f"Database not locked. node:{self!r}"

        # start the registration early to speed up the start
        if self.config["transport_type"] == "udp":
            endpoint_registration_greenlet = gevent.spawn(
                self.discovery.register,
                self.address,
                self.config["transport"]["udp"]["external_ip"],
                self.config["transport"]["udp"]["external_port"],
            )

        self.maybe_upgrade_db()

        storage = sqlite.SerializedSQLiteStorage(
            database_path=self.database_path, serializer=serialize.JSONSerializer()
        )
        storage.update_version()
        storage.log_run()
        self.wal = wal.restore_to_state_change(
            transition_function=node.state_transition,
            storage=storage,
            state_change_identifier="latest",
        )

        if self.wal.state_manager.current_state is None:
            log.debug(
                "No recoverable state available, creating inital state.", node=pex(self.address)
            )
            # On first run Raiden needs to fetch all events for the payment
            # network, to reconstruct all token network graphs and find opened
            # channels
            last_log_block_number = self.query_start_block
            last_log_block_hash = self.chain.client.blockhash_from_blocknumber(
                last_log_block_number
            )

            state_change = ActionInitChain(
                pseudo_random_generator=random.Random(),
                block_number=last_log_block_number,
                block_hash=last_log_block_hash,
                our_address=self.chain.node_address,
                chain_id=self.chain.network_id,
            )
            self.handle_and_track_state_change(state_change)

            payment_network = PaymentNetworkState(
                self.default_registry.address,
                [],  # empty list of token network states as it's the node's startup
            )
            state_change = ContractReceiveNewPaymentNetwork(
                transaction_hash=constants.EMPTY_HASH,
                payment_network=payment_network,
                block_number=last_log_block_number,
                block_hash=last_log_block_hash,
            )
            self.handle_and_track_state_change(state_change)
        else:
            # The `Block` state change is dispatched only after all the events
            # for that given block have been processed, filters can be safely
            # installed starting from this position without losing events.
            last_log_block_number = views.block_number(self.wal.state_manager.current_state)
            log.debug(
                "Restored state from WAL",
                last_restored_block=last_log_block_number,
                node=pex(self.address),
            )

            known_networks = views.get_payment_network_identifiers(views.state_from_raiden(self))
            if known_networks and self.default_registry.address not in known_networks:
                configured_registry = pex(self.default_registry.address)
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

        self._initialize_payment_statuses(chain_state)
        self._initialize_transactions_queues(chain_state)
        self._initialize_messages_queues(chain_state)
        self._initialize_whitelists(chain_state)
        self._initialize_monitoring_services_queue(chain_state)
        self._initialize_ready_to_processed_events()

        if self.config["transport_type"] == "udp":
            endpoint_registration_greenlet.get()  # re-raise if exception occurred

        # Start the side-effects:
        # - React to blockchain events
        # - React to incoming messages
        # - Send pending transactions
        # - Send pending message
        self.alarm.link_exception(self.on_error)
        self.transport.link_exception(self.on_error)
        self._start_transport(chain_state)
        self._start_alarm_task()

        log.debug("Raiden Service started", node=pex(self.address))
        super().start()

    def _run(self, *args, **kwargs):  # pylint: disable=method-hidden
        """ Busy-wait on long-lived subtasks/greenlets, re-raise if any error occurs """
        self.greenlet.name = f"RaidenService._run node:{pex(self.address)}"
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

        # Close storage DB to release internal DB lock
        self.wal.storage.conn.close()

        if self.db_lock is not None:
            self.db_lock.release()

        log.debug("Raiden Service stopped", node=pex(self.address))

    @property
    def confirmation_blocks(self):
        return self.config["blockchain"]["confirmation_blocks"]

    @property
    def privkey(self):
        return self.chain.client.privkey

    def add_pending_greenlet(self, greenlet: Greenlet):
        """ Ensures an error on the passed greenlet crashes self/main greenlet. """

        def remove(_):
            self.greenlets.remove(greenlet)

        self.greenlets.append(greenlet)
        greenlet.link_exception(self.on_error)
        greenlet.link_value(remove)

    def __repr__(self):
        return f"<{self.__class__.__name__} node:{pex(self.address)}>"

    def _start_transport(self, chain_state: ChainState):
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

    def _start_alarm_task(self):
        """Start the alarm task.

        Note:
            The alarm task must be started only when processing events is
            allowed, otherwise side-effects of blockchain events will be
            ignored.
        """
        assert self.ready_to_process_events, f"Event procossing disable. node:{self!r}"
        self.alarm.start()

    def _initialize_ready_to_processed_events(self):
        assert not self.transport
        assert not self.alarm

        # This flag /must/ be set to true before the transport or the alarm task is started
        self.ready_to_process_events = True

    def get_block_number(self) -> BlockNumber:
        assert self.wal, f"WAL object not yet initialized. node:{self!r}"
        return views.block_number(self.wal.state_manager.current_state)

    def on_message(self, message: Message):
        self.message_handler.on_message(self, message)

    def handle_and_track_state_change(self, state_change: StateChange):
        """ Dispatch the state change and does not handle the exceptions.

        When the method is used the exceptions are tracked and re-raised in the
        raiden service thread.
        """
        for greenlet in self.handle_state_change(state_change):
            self.add_pending_greenlet(greenlet)

    def handle_state_change(self, state_change: StateChange) -> List[Greenlet]:
        """ Dispatch the state change and return the processing threads.

        Use this for error reporting, failures in the returned greenlets,
        should be re-raised using `gevent.joinall` with `raise_error=True`.
        """
        assert self.wal, f"WAL not restored. node:{self!r}"
        log.debug(
            "State change",
            node=pex(self.address),
            state_change=_redact_secret(serialize.JSONSerializer.serialize(state_change)),
        )

        old_state = views.state_from_raiden(self)
        new_state, raiden_event_list = self.wal.log_and_dispatch(state_change)

        for changed_balance_proof in views.detect_balance_proof_change(old_state, new_state):
            update_services_from_balance_proof(self, new_state, changed_balance_proof)

        log.debug(
            "Raiden events",
            node=pex(self.address),
            raiden_events=[
                _redact_secret(serialize.JSONSerializer.serialize(event))
                for event in raiden_event_list
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

    def _handle_event(self, chain_state: ChainState, raiden_event: RaidenEvent):
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

    def set_node_network_state(self, node_address: Address, network_state: str):
        state_change = ActionChangeNodeNetworkState(node_address, network_state)
        self.handle_and_track_state_change(state_change)

    def start_health_check_for(self, node_address: Address):
        """Start health checking `node_address`.

        This function is a noop during initialization, because health checking
        can be started as a side effect of some events (e.g. new channel). For
        these cases the healthcheck will be started by
        `start_neighbours_healthcheck`.
        """
        if self.transport:
            self.transport.start_health_check(node_address)

    def _callback_new_block(self, latest_block: Dict):
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
            confirmed_block_number = max(
                GENESIS_BLOCK_NUMBER,
                latest_block_number - self.config["blockchain"]["confirmation_blocks"],
            )
            confirmed_block = self.chain.client.web3.eth.getBlock(confirmed_block_number)

            # These state changes will be procesed with a block_number which is
            # /larger/ than the ChainState's block_number.
            for event in self.blockchain_events.poll_blockchain_events(confirmed_block_number):
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
                gas_limit=confirmed_block["gasLimit"],
                block_hash=BlockHash(bytes(confirmed_block["hash"])),
            )

            # Note: It's important to /not/ block here, because this function
            # can be called from the alarm task greenlet, which should not
            # starve.
            self.handle_and_track_state_change(state_change)

    def _initialize_transactions_queues(self, chain_state: ChainState):
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
            "Processing pending transactions",
            num_pending_transactions=len(pending_transactions),
            node=pex(self.address),
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
            except RaidenUnrecoverableError as e:
                log_unrecoverable = (
                    self.config["environment_type"] == Environment.PRODUCTION
                    and not self.config["unrecoverable_error_should_crash"]
                )
                if log_unrecoverable:
                    log.error(str(e))
                else:
                    raise

    def _initialize_payment_statuses(self, chain_state: ChainState):
        """ Re-initialize targets_to_identifiers_to_statuses.

        Restore the PaymentStatus for any pending payment. This is not tied to
        a specific protocol message but to the lifecycle of a payment, i.e.
        the status is re-created if a payment itself has not completed.
        """

        with self.payment_identifier_lock:
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
                    token_network_identifier=TokenNetworkID(
                        balance_proof.token_network_identifier
                    ),
                    payment_done=AsyncResult(),
                )

    def _initialize_messages_queues(self, chain_state: ChainState):
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

        for queue_identifier, event_queue in events_queues.items():
            self.start_health_check_for(queue_identifier.recipient)

            for event in event_queue:
                message = message_from_sendevent(event)
                self.sign(message)
                self.transport.send_async(queue_identifier, message)

    def _initialize_monitoring_services_queue(self, chain_state: ChainState):
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

        current_balance_proofs = views.detect_balance_proof_change(
            old_state=ChainState(
                pseudo_random_generator=chain_state.pseudo_random_generator,
                block_number=GENESIS_BLOCK_NUMBER,
                block_hash=constants.EMPTY_HASH,
                our_address=chain_state.our_address,
                chain_id=chain_state.chain_id,
            ),
            current_state=chain_state,
        )
        for balance_proof in current_balance_proofs:
            update_services_from_balance_proof(self, chain_state, balance_proof)

    def _initialize_whitelists(self, chain_state: ChainState):
        """ Whitelist neighbors and mediated transfer targets on transport """

        for neighbour in views.all_neighbour_nodes(chain_state):
            if neighbour == ConnectionManager.BOOTSTRAP_ADDR:
                continue
            self.transport.whitelist(neighbour)

        events_queues = views.get_all_messagequeues(chain_state)

        for event_queue in events_queues.values():
            for event in event_queue:
                if isinstance(event, SendLockedTransfer):
                    transfer = event.transfer
                    if transfer.initiator == self.address:
                        self.transport.whitelist(address=transfer.target)

    def sign(self, message: Message):
        """ Sign message inplace. """
        if not isinstance(message, SignedMessage):
            raise ValueError("{} is not signable.".format(repr(message)))

        message.sign(self.signer)

    def install_all_blockchain_filters(
        self,
        token_network_registry_proxy: TokenNetworkRegistry,
        secret_registry_proxy: SecretRegistry,
        from_block: BlockNumber,
    ):
        with self.event_poll_lock:
            node_state = views.state_from_raiden(self)
            token_networks = views.get_token_network_identifiers(
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

            for token_network in token_networks:
                token_network_proxy = self.chain.token_network(TokenNetworkAddress(token_network))
                self.blockchain_events.add_token_network_listener(
                    token_network_proxy=token_network_proxy,
                    contract_manager=self.contract_manager,
                    from_block=from_block,
                )

    def connection_manager_for_token_network(
        self, token_network_identifier: TokenNetworkID
    ) -> ConnectionManager:
        if not is_binary_address(token_network_identifier):
            raise InvalidAddress("token address is not valid.")

        known_token_networks = views.get_token_network_identifiers(
            views.state_from_raiden(self), self.default_registry.address
        )

        if token_network_identifier not in known_token_networks:
            raise InvalidAddress("token is not registered.")

        manager = self.tokennetworkids_to_connectionmanagers.get(token_network_identifier)

        if manager is None:
            manager = ConnectionManager(self, token_network_identifier)
            self.tokennetworkids_to_connectionmanagers[token_network_identifier] = manager

        return manager

    def mediated_transfer_async(
        self,
        token_network_identifier: TokenNetworkID,
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
                secret = EMPTY_SECRET

        payment_status = self.start_mediated_transfer_with_secret(
            token_network_identifier=token_network_identifier,
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
        token_network_identifier: TokenNetworkID,
        amount: PaymentAmount,
        fee: FeeAmount,
        target: TargetAddress,
        identifier: PaymentID,
        secret: Secret,
        secrethash: SecretHash = None,
    ) -> PaymentStatus:

        if secrethash is None:
            secrethash = sha3(secret)
        elif secrethash != sha3(secret):
            raise InvalidSecretHash("provided secret and secret_hash do not match.")

        if len(secret) != SECRET_LENGTH:
            raise InvalidSecret("secret of invalid length.")

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
                f"Attempted to initiate a locked transfer with secrethash {pex(secrethash)}."
                f" That secret is already registered onchain."
            )

        self.start_health_check_for(Address(target))

        if identifier is None:
            identifier = create_default_identifier()

        with self.payment_identifier_lock:
            payment_status = self.targets_to_identifiers_to_statuses[target].get(identifier)
            if payment_status:
                payment_status_matches = payment_status.matches(token_network_identifier, amount)
                if not payment_status_matches:
                    raise PaymentConflict("Another payment with the same id is in flight")

                return payment_status

            payment_status = PaymentStatus(
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
            transfer_secrethash=secrethash,
            transfer_fee=fee,
            token_network_identifier=token_network_identifier,
            target_address=target,
        )

        # Dispatch the state change even if there are no routes to create the
        # wal entry.
        self.handle_and_track_state_change(init_initiator_statechange)

        return payment_status

    def mediate_mediated_transfer(self, transfer: LockedTransfer):
        init_mediator_statechange = mediator_init(self, transfer)
        self.handle_and_track_state_change(init_mediator_statechange)

    def target_mediated_transfer(self, transfer: LockedTransfer):
        self.start_health_check_for(Address(transfer.initiator))
        init_target_statechange = target_init(transfer)
        self.handle_and_track_state_change(init_target_statechange)

    def maybe_upgrade_db(self) -> None:
        manager = UpgradeManager(
            db_filename=self.database_path, raiden=self, web3=self.chain.client.web3
        )
        manager.run()
