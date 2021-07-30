import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, List

import gevent
import structlog

from raiden.storage.restore import get_state_change_with_transfer_by_secrethash
from raiden.transfer import channel, views
from raiden.transfer.events import EventPaymentReceivedSuccess
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.events import EventUnlockClaimFailed
from raiden.transfer.mediated_transfer.state_change import ActionInitMediator, ActionInitTarget
from raiden.transfer.state import (
    CHANNEL_AFTER_CLOSE_STATES,
    ChainState,
    ChannelState,
    NettingChannelEndState,
    NettingChannelState,
    TransactionExecutionStatus,
)
from raiden.transfer.state_change import (
    ContractReceiveChannelWithdraw,
    ContractReceiveSecretReveal,
)
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import (
    Address,
    Any,
    BlockNumber,
    Callable,
    ChannelID,
    Mapping,
    Optional,
    PaymentAmount,
    PaymentID,
    SecretHash,
    Sequence,
    TokenAddress,
    TokenAmount,
    TokenNetworkRegistryAddress,
    WithdrawAmount,
)

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService  # pylint: disable=unused-import

log = structlog.get_logger(__name__)

ALARM_TASK_ERROR_MSG = "Waiting relies on alarm task polling to update the node's internal state."
TRANSPORT_ERROR_MSG = "Waiting for protocol messages requires a running transport."


def _get_channel_state_by_partner_address(
    chain_state: ChainState,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    partner_address: Address,
) -> Optional[NettingChannelState]:
    token_network = views.get_token_network_by_token_address(
        chain_state=chain_state,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )

    if token_network is None:
        raise ValueError(
            f"The token {to_checksum_address(token_address)} is not registered on "
            f"the network {to_checksum_address(token_network_registry_address)}."
        )
    return views.get_channelstate_by_token_network_and_partner(
        chain_state, token_network.address, partner_address
    )


class ChannelStateCondition(ABC):
    @abstractmethod
    def evaluate_condition(
        self, chain_state: ChainState, channel_state: Optional[NettingChannelState]
    ) -> bool:
        pass

    def __call__(
        self, chain_state: ChainState, channel_state: Optional[NettingChannelState]
    ) -> bool:
        return self.evaluate_condition(chain_state, channel_state)


@dataclass
class ChannelHasDeposit(ChannelStateCondition):
    target_address: Address
    target_balance: TokenAmount

    def evaluate_condition(
        self, chain_state: ChainState, channel_state: Optional[NettingChannelState]
    ) -> bool:
        if channel_state is None:
            return False
        if self.target_address == channel_state.our_state.address:
            return channel_state.our_state.contract_balance >= self.target_balance
        elif self.target_address == channel_state.partner_state.address:
            return channel_state.partner_state.contract_balance >= self.target_balance
        else:
            raise ValueError("target_address must be one of the channel participants")


@dataclass
class ChannelExists(ChannelStateCondition):
    def evaluate_condition(
        self, chain_state: ChainState, channel_state: Optional[NettingChannelState]
    ) -> bool:
        return channel_state is not None


@dataclass
class ChannelHasPaymentBalance(ChannelStateCondition):
    target_address: Address
    target_balance: TokenAmount

    def evaluate_condition(
        self, chain_state: ChainState, channel_state: Optional[NettingChannelState]
    ) -> bool:
        def get_balance(end_state: NettingChannelEndState) -> TokenAmount:
            if end_state.balance_proof:
                return end_state.balance_proof.transferred_amount
            else:
                return TokenAmount(0)

        if channel_state is None:
            return False
        if self.target_address == channel_state.our_state.address:
            return get_balance(channel_state.our_state) >= self.target_balance
        elif self.target_address == channel_state.partner_state.address:
            return get_balance(channel_state.partner_state) >= self.target_balance
        else:
            raise ValueError("target_address must be one of the channel participants")


@dataclass
class ChannelInTargetStates(ChannelStateCondition):
    target_states: Sequence[ChannelState]

    def evaluate_condition(
        self, chain_state: ChainState, channel_state: Optional[NettingChannelState]
    ) -> bool:
        if channel_state is None:
            # XXX this was reversed before, why?
            return False
        return channel.get_status(channel_state) in self.target_states


@dataclass
class ChannelExpiredCoopSettle(ChannelStateCondition):
    coop_settle_initiator_address: Address
    participant_total_withdraw: WithdrawAmount
    partner_total_withdraw: WithdrawAmount
    initiation_block: BlockNumber

    def evaluate_condition(
        self, chain_state: ChainState, channel_state: Optional[NettingChannelState]
    ) -> bool:
        if channel_state is None:
            return False
        if self.coop_settle_initiator_address is channel_state.our_state.address:
            channel_end_state = channel_state.our_state
        elif self.coop_settle_initiator_address is channel_state.partner_state.address:
            channel_end_state = channel_state.partner_state
        else:
            raise ValueError("target_address must be one of the channel participants")
        try:
            next(
                candidate
                for candidate in channel_end_state.expired_coop_settles
                if candidate.total_withdraw_partner == self.partner_total_withdraw
                and candidate.total_withdraw_participant == self.participant_total_withdraw
                and candidate.expiration > self.initiation_block
            )
            return True
        except StopIteration:
            return False


@dataclass
class ChannelCoopSettleSuccess(ChannelStateCondition):
    coop_settle_initiator_address: Address

    def evaluate_condition(
        self, chain_state: ChainState, channel_state: Optional[NettingChannelState]
    ) -> bool:
        if channel_state is None:
            return False
        if self.coop_settle_initiator_address is channel_state.our_state.address:
            channel_end_state = channel_state.our_state
        elif self.coop_settle_initiator_address is channel_state.partner_state.address:
            channel_end_state = channel_state.partner_state
        else:
            raise ValueError("target_address must be one of the channel participants")
        if channel_end_state.initiated_coop_settle:
            if channel_end_state.initiated_coop_settle.transaction:
                return (
                    channel_end_state.initiated_coop_settle.transaction.result
                    is TransactionExecutionStatus.SUCCESS
                )
        return False


@dataclass
class And(ChannelStateCondition):
    conditions: List[ChannelStateCondition]

    def evaluate_condition(
        self, chain_state: ChainState, channel_state: Optional[NettingChannelState]
    ) -> bool:
        return all([condition(chain_state, channel_state) for condition in self.conditions])


@dataclass
class Or(ChannelStateCondition):
    conditions: List[ChannelStateCondition]

    def evaluate_condition(
        self, chain_state: ChainState, channel_state: Optional[NettingChannelState]
    ) -> bool:
        return any([condition(chain_state, channel_state) for condition in self.conditions])


@dataclass
class ChannelStateWaiter:
    raiden: "RaidenService"
    retry_timeout: float
    token_network_registry_address: TokenNetworkRegistryAddress
    token_address: TokenAddress
    partner_address: Address

    def _get_current_chain_state(self) -> ChainState:
        return views.state_from_raiden(self.raiden)

    def _get_channel_state(self, chain_state: ChainState) -> Optional[NettingChannelState]:
        return _get_channel_state_by_partner_address(
            chain_state,
            self.token_network_registry_address,
            self.token_address,
            self.partner_address,
        )

    def _log_details(self, condition: ChannelStateCondition) -> Mapping[str, Any]:
        log_details = {
            "token_network_registry_address": self.token_network_registry_address,
            "condition": str(condition),
        }
        return log_details

    def wait(self, condition: ChannelStateCondition) -> None:
        chain_state = self._get_current_chain_state()
        while condition(chain_state, self._get_channel_state(chain_state)) is not True:
            assert self.raiden, ALARM_TASK_ERROR_MSG
            assert self.raiden.alarm, ALARM_TASK_ERROR_MSG
            log.debug(str(self), **self._log_details(condition))
            gevent.sleep(self.retry_timeout)
            chain_state = self._get_current_chain_state()


def _get_canonical_identifier_by_channel_id(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    channel_id: ChannelID,
) -> CanonicalIdentifier:
    chain_state = views.state_from_raiden(raiden)
    token_network = views.get_token_network_by_token_address(
        chain_state=chain_state,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )

    if token_network is None:
        raise ValueError(
            f"The token {to_checksum_address(token_address)} is not registered on "
            f"the network {to_checksum_address(token_network_registry_address)}."
        )

    return CanonicalIdentifier(
        chain_identifier=chain_state.chain_id,
        token_network_address=token_network.address,
        channel_identifier=channel_id,
    )


def wait_until(func: Callable, wait_for: float = None, sleep_for: float = 0.5) -> Any:
    """Test for a function and wait for it to return a truth value or to timeout.
    Returns the value or None if a timeout is given and the function didn't return
    inside time timeout
    Args:
        func: a function to be evaluated, use lambda if parameters are required
        wait_for: the maximum time to wait, or None for an infinite loop
        sleep_for: how much to gevent.sleep between calls
    Returns:
        func(): result of func, if truth value, or None"""
    res = func()

    if res:
        return res

    if wait_for:
        deadline = time.time() + wait_for
        while not res and time.time() <= deadline:
            gevent.sleep(sleep_for)
            res = func()

    else:
        while not res:
            gevent.sleep(sleep_for)
            res = func()

    return res


def wait_for_block(
    raiden: "RaidenService", block_number: BlockNumber, retry_timeout: float
) -> None:  # pragma: no unittest
    current = raiden.get_block_number()

    log_details = {
        "node": to_checksum_address(raiden.address),
        "target_block_number": block_number,
    }
    while current < block_number:
        assert raiden, ALARM_TASK_ERROR_MSG
        assert raiden.alarm, ALARM_TASK_ERROR_MSG

        log.debug("wait_for_block", current_block_number=current, **log_details)
        gevent.sleep(retry_timeout)
        current = raiden.get_block_number()


def wait_for_newchannel(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    partner_address: Address,
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until the channel with partner_address is registered.

    Note:
        This does not time out, use gevent.Timeout.
    """
    ChannelStateWaiter(
        raiden, retry_timeout, token_network_registry_address, token_address, partner_address
    ).wait(ChannelExists())


def wait_for_participant_deposit(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    partner_address: Address,
    target_address: Address,
    target_balance: TokenAmount,
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until a given channels balance exceeds the target balance.

    Note:
        This does not time out, use gevent.Timeout.
    """
    condition = ChannelHasDeposit(target_address, target_balance)
    ChannelStateWaiter(
        raiden, retry_timeout, token_network_registry_address, token_address, partner_address
    ).wait(condition)


def wait_single_channel_deposit(
    app_deposit: "RaidenService",
    app_partner: "RaidenService",
    registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    total_deposit: TokenAmount,
    retry_timeout: float,
) -> None:
    """Wait until a deposit of `total_deposit` for app_deposit is seen by both apps"""
    wait_for_participant_deposit(
        raiden=app_deposit,
        token_network_registry_address=registry_address,
        token_address=token_address,
        partner_address=app_partner.address,
        target_address=app_deposit.address,
        target_balance=total_deposit,
        retry_timeout=retry_timeout,
    )
    wait_for_participant_deposit(
        raiden=app_partner,
        token_network_registry_address=registry_address,
        token_address=token_address,
        partner_address=app_deposit.address,
        target_address=app_deposit.address,
        target_balance=total_deposit,
        retry_timeout=retry_timeout,
    )


def wait_both_channel_deposit(
    app_deposit: "RaidenService",
    app_partner: "RaidenService",
    registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    total_deposit: TokenAmount,
    retry_timeout: float,
) -> None:
    """Wait until a deposit of `total_deposit` for both apps is seen by both apps"""
    wait_single_channel_deposit(
        app_deposit=app_deposit,
        app_partner=app_partner,
        registry_address=registry_address,
        token_address=token_address,
        total_deposit=total_deposit,
        retry_timeout=retry_timeout,
    )
    wait_single_channel_deposit(
        app_deposit=app_partner,
        app_partner=app_deposit,
        registry_address=registry_address,
        token_address=token_address,
        total_deposit=total_deposit,
        retry_timeout=retry_timeout,
    )


def wait_for_payment_balance(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    partner_address: Address,
    target_address: Address,
    target_balance: TokenAmount,
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until a given channel's balance exceeds the target balance.

    Note:
        This does not time out, use gevent.Timeout.
    """
    condition = ChannelHasPaymentBalance(target_address, target_balance)
    waiter = ChannelStateWaiter(
        raiden, retry_timeout, token_network_registry_address, token_address, partner_address
    )
    waiter.wait(condition)


def wait_for_channels(
    raiden: "RaidenService",
    canonical_id_to_condition: Mapping[CanonicalIdentifier, ChannelStateCondition],
    retry_timeout: float,
    timeout: Optional[int] = None,
) -> None:
    wait_tasks = list()
    chain_state = views.state_from_raiden(raiden)
    for canonical_id, condition in canonical_id_to_condition.items():
        channel_state = views.get_channelstate_by_canonical_identifier(chain_state, canonical_id)
        assert channel_state is not None, "Can't wait for nonexisting channels"
        waiter = ChannelStateWaiter(
            raiden,
            retry_timeout,
            channel_state.token_network_registry_address,
            channel_state.token_address,
            channel_state.partner_state.address,
        )
        task = gevent.spawn(waiter.wait, condition)
        wait_tasks.append(task)
    gevent.joinall(wait_tasks, timeout=timeout, raise_error=True)


def wait_for_channel_in_states(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    channel_ids: List[ChannelID],
    retry_timeout: float,
    target_states: Sequence[ChannelState],
) -> None:

    canonical_id_to_condition = dict()
    condition = ChannelInTargetStates(target_states)
    for channel_id in channel_ids:
        canonical_id = _get_canonical_identifier_by_channel_id(
            raiden, token_network_registry_address, token_address, channel_id
        )
        if canonical_id is not None:
            canonical_id_to_condition[canonical_id] = condition

    wait_for_channels(
        raiden,
        canonical_id_to_condition,
        retry_timeout,
    )


def wait_for_close(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    channel_ids: List[ChannelID],
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until all channels are closed.

    Note:
        This does not time out, use gevent.Timeout.
    """
    return wait_for_channel_in_states(
        raiden=raiden,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
        channel_ids=channel_ids,
        retry_timeout=retry_timeout,
        target_states=CHANNEL_AFTER_CLOSE_STATES,
    )


def wait_for_token_network(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until the token network is visible to the RaidenService.

    Note:
        This does not time out, use gevent.Timeout.
    """
    token_network = views.get_token_network_by_token_address(
        views.state_from_raiden(raiden), token_network_registry_address, token_address
    )
    log_details = {
        "token_network_registry_address": to_checksum_address(token_network_registry_address),
        "token_address": to_checksum_address(token_address),
    }
    while token_network is None:
        assert raiden, ALARM_TASK_ERROR_MSG
        assert raiden.alarm, ALARM_TASK_ERROR_MSG

        log.debug("wait_for_token_network", **log_details)
        gevent.sleep(retry_timeout)
        token_network = views.get_token_network_by_token_address(
            views.state_from_raiden(raiden), token_network_registry_address, token_address
        )


def wait_for_settle(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    channel_ids: List[ChannelID],
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until all channels are settled.

    Note:
        This does not time out, use gevent.Timeout.
    """
    return wait_for_channel_in_states(
        raiden=raiden,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
        channel_ids=channel_ids,
        retry_timeout=retry_timeout,
        target_states=(ChannelState.STATE_SETTLED,),
    )


class TransferWaitResult(Enum):
    SECRET_REGISTERED_ONCHAIN = "secret registered onchain"
    UNLOCKED = "unlocked"
    UNLOCK_FAILED = "unlock_failed"


def wait_for_received_transfer_result(
    raiden: "RaidenService",
    payment_identifier: PaymentID,
    amount: PaymentAmount,
    retry_timeout: float,
    secrethash: SecretHash,
) -> TransferWaitResult:  # pragma: no unittest
    """Wait for the result of a transfer with the specified identifier
    and/or secrethash. Possible results are onchain secret registration,
    successful unlock and failed unlock. For a successful unlock, the
    amount is also checked.

    Note:
        This does not time out, use gevent.Timeout.
    """
    log_details = {"payment_identifier": payment_identifier, "amount": amount}

    assert raiden, TRANSPORT_ERROR_MSG
    assert raiden.wal, TRANSPORT_ERROR_MSG
    assert raiden.transport, TRANSPORT_ERROR_MSG
    stream = raiden.wal.storage.get_state_changes_stream(retry_timeout=retry_timeout)

    result = None
    while result is None:

        state_events = raiden.wal.storage.get_events()
        for event in state_events:
            unlocked = (
                isinstance(event, EventPaymentReceivedSuccess)
                and event.identifier == payment_identifier
                and PaymentAmount(event.amount) == amount
            )
            if unlocked:
                result = TransferWaitResult.UNLOCKED
                break
            claim_failed = (
                isinstance(event, EventUnlockClaimFailed)
                and event.identifier == payment_identifier
                and event.secrethash == secrethash
            )
            if claim_failed:
                result = TransferWaitResult.UNLOCK_FAILED
                break

        state_changes = next(stream)
        for state_change in state_changes:
            registered_onchain = (
                isinstance(state_change, ContractReceiveSecretReveal)
                and state_change.secrethash == secrethash
            )
            if registered_onchain:
                state_change_record = get_state_change_with_transfer_by_secrethash(
                    raiden.wal.storage, secrethash
                )
                assert state_change_record is not None, "Could not find state change for screthash"
                msg = "Expected ActionInitMediator/ActionInitTarget not found in state changes."
                expected_types = (ActionInitMediator, ActionInitTarget)
                assert isinstance(state_change_record.data, expected_types), msg

                transfer = None
                if isinstance(state_change_record.data, ActionInitMediator):
                    transfer = state_change_record.data.from_transfer
                if isinstance(state_change_record.data, ActionInitTarget):
                    transfer = state_change_record.data.transfer

                if transfer is not None and raiden.get_block_number() <= transfer.lock.expiration:
                    return TransferWaitResult.SECRET_REGISTERED_ONCHAIN

        log.debug("wait_for_transfer_result", **log_details)
        gevent.sleep(retry_timeout)

    return result  # type: ignore


def wait_for_withdraw_complete(
    raiden: "RaidenService",
    canonical_identifier: CanonicalIdentifier,
    total_withdraw: WithdrawAmount,
    retry_timeout: float,
) -> None:
    """Wait until a withdraw with a specific identifier and amount
    is seen in the WAL.

    Note:
        This does not time out, use gevent.Timeout.
    """
    log_details = {
        "canonical_identifier": canonical_identifier,
        "target_total_withdraw": total_withdraw,
    }
    assert raiden, TRANSPORT_ERROR_MSG
    assert raiden.wal, TRANSPORT_ERROR_MSG
    assert raiden.transport, TRANSPORT_ERROR_MSG
    stream = raiden.wal.storage.get_state_changes_stream(retry_timeout=retry_timeout)

    while True:
        state_changes = next(stream)

        for state_change in state_changes:
            found = (
                isinstance(state_change, ContractReceiveChannelWithdraw)
                and state_change.total_withdraw == total_withdraw
                and state_change.canonical_identifier == canonical_identifier
            )

            if found:
                return

        log.debug("wait_for_withdraw_complete", **log_details)
        gevent.sleep(retry_timeout)
