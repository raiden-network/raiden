import gevent
import structlog
from eth_utils import is_binary_address, to_checksum_address

import raiden.blockchain.events as blockchain_events
from raiden import waiting
from raiden.api.exceptions import ChannelNotFound, NonexistingChannel
from raiden.constants import GENESIS_BLOCK_NUMBER, NULL_ADDRESS_BYTES, UINT256_MAX
from raiden.exceptions import (
    AlreadyRegisteredTokenAddress,
    DepositMismatch,
    DepositOverLimit,
    DuplicatedChannelError,
    InsufficientFunds,
    InsufficientGasReserve,
    InvalidAmount,
    InvalidBinaryAddress,
    InvalidRevealTimeout,
    InvalidSecret,
    InvalidSecretHash,
    InvalidSettleTimeout,
    InvalidTokenAddress,
    RaidenRecoverableError,
    TokenNetworkDeprecated,
    TokenNotRegistered,
    UnexpectedChannelState,
    UnknownTokenAddress,
    WithdrawMismatch,
)
from raiden.messages.monitoring_service import RequestMonitoring
from raiden.settings import DEFAULT_RETRY_TIMEOUT
from raiden.storage.utils import TimestampedEvent
from raiden.transfer import channel, views
from raiden.transfer.architecture import Event, StateChange, TransferTask
from raiden.transfer.events import (
    EventPaymentReceivedSuccess,
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
)
from raiden.transfer.mediated_transfer.tasks import InitiatorTask, MediatorTask, TargetTask
from raiden.transfer.state import (
    BalanceProofSignedState,
    ChannelState,
    NettingChannelState,
    NetworkState,
)
from raiden.transfer.state_change import ActionChannelClose
from raiden.utils import create_default_identifier
from raiden.utils.gas_reserve import has_enough_gas_reserve
from raiden.utils.testnet import MintingMethod, call_minting_method, token_minting_proxy
from raiden.utils.typing import (
    TYPE_CHECKING,
    Address,
    Any,
    BlockSpecification,
    BlockTimeout,
    ChannelID,
    Dict,
    List,
    LockedTransferType,
    NetworkTimeout,
    Optional,
    PaymentAmount,
    PaymentID,
    Secret,
    SecretHash,
    T_Secret,
    T_SecretHash,
    TargetAddress,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    TransactionHash,
    Tuple,
    WithdrawAmount,
)

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService, PaymentStatus

log = structlog.get_logger(__name__)

EVENTS_PAYMENT_HISTORY_RELATED = (
    EventPaymentSentSuccess,
    EventPaymentSentFailed,
    EventPaymentReceivedSuccess,
)


def event_filter_for_payments(event: Event, partner_address: Address = None) -> bool:
    """Filters payment history related events depending on partner_address argument

    - If no other args are given, all payment related events match
    - If a token network identifier is given then only payment events for that match
    - If a partner is also given then if the event is a payment sent event and the
      target matches it's returned. If it's a payment received and the initiator matches
      then it's returned.
    """

    sent_and_target_matches = isinstance(
        event, (EventPaymentSentFailed, EventPaymentSentSuccess)
    ) and (partner_address is None or event.target == partner_address)
    received_and_initiator_matches = isinstance(event, EventPaymentReceivedSuccess) and (
        partner_address is None or event.initiator == partner_address
    )
    return sent_and_target_matches or received_and_initiator_matches


def flatten_transfer(transfer: LockedTransferType, role: str) -> Dict[str, Any]:
    return {
        "payment_identifier": str(transfer.payment_identifier),
        "token_address": to_checksum_address(transfer.token),
        "token_network_address": to_checksum_address(transfer.balance_proof.token_network_address),
        "channel_identifier": str(transfer.balance_proof.channel_identifier),
        "initiator": to_checksum_address(transfer.initiator),
        "target": to_checksum_address(transfer.target),
        "transferred_amount": str(transfer.balance_proof.transferred_amount),
        "locked_amount": str(transfer.balance_proof.locked_amount),
        "role": role,
    }


def get_transfer_from_task(
    secrethash: SecretHash, transfer_task: TransferTask
) -> Tuple[LockedTransferType, str]:
    role = views.role_from_transfer_task(transfer_task)
    transfer: LockedTransferType
    if isinstance(transfer_task, InitiatorTask):
        transfer = transfer_task.manager_state.initiator_transfers[secrethash].transfer
    elif isinstance(transfer_task, MediatorTask):
        pairs = transfer_task.mediator_state.transfers_pair
        if pairs:
            transfer = pairs[-1].payer_transfer
        elif transfer_task.mediator_state.waiting_transfer:
            transfer = transfer_task.mediator_state.waiting_transfer.transfer
    elif isinstance(transfer_task, TargetTask):
        transfer = transfer_task.target_state.transfer
    else:  # pragma: no unittest
        raise ValueError("get_transfer_from_task for a non TransferTask argument")

    return transfer, role


def transfer_tasks_view(
    transfer_tasks: Dict[SecretHash, TransferTask],
    token_address: TokenAddress = None,
    channel_id: ChannelID = None,
) -> List[Dict[str, Any]]:
    view = list()

    for secrethash, transfer_task in transfer_tasks.items():
        transfer, role = get_transfer_from_task(secrethash, transfer_task)

        if transfer is None:
            continue
        if token_address is not None:
            if transfer.token != token_address:
                continue
            elif channel_id is not None:
                if transfer.balance_proof.channel_identifier != channel_id:
                    continue

        view.append(flatten_transfer(transfer, role))

    return view


class RaidenAPI:  # pragma: no unittest
    # pylint: disable=too-many-public-methods

    def __init__(self, raiden: "RaidenService"):
        self.raiden = raiden

    @property
    def address(self) -> Address:
        return self.raiden.address

    def get_channel(
        self,
        registry_address: TokenNetworkRegistryAddress,
        token_address: TokenAddress,
        partner_address: Address,
    ) -> NettingChannelState:
        if not is_binary_address(token_address):
            raise InvalidBinaryAddress("Expected binary address format for token in get_channel")

        if not is_binary_address(partner_address):
            raise InvalidBinaryAddress("Expected binary address format for partner in get_channel")

        channel_list = self.get_channel_list(registry_address, token_address, partner_address)
        assert len(channel_list) <= 1

        if not channel_list:
            msg = (
                f"Channel with partner '{to_checksum_address(partner_address)}' "
                f"for token '{to_checksum_address(token_address)}' could not be "
                f"found."
            )
            raise ChannelNotFound(msg)

        return channel_list[0]

    def token_network_register(
        self,
        registry_address: TokenNetworkRegistryAddress,
        token_address: TokenAddress,
        channel_participant_deposit_limit: TokenAmount,
        token_network_deposit_limit: TokenAmount,
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ) -> TokenNetworkAddress:
        """Register the `token_address` in the blockchain. If the address is already
           registered but the event has not been processed this function will block
           until the next block to make sure the event is processed.

        Raises:
            InvalidBinaryAddress: If the registry_address or token_address is not a valid address.
            AlreadyRegisteredTokenAddress: If the token is already registered.
            RaidenRecoverableError: If the register transaction failed, this may
                happen because the account has not enough balance to pay for the
                gas or this register call raced with another transaction and lost.
            InvalidTokenAddress: If token_address is the null address (0x000000....00).
        """

        if not is_binary_address(registry_address):
            raise InvalidBinaryAddress("registry_address must be a valid address in binary")

        if not is_binary_address(token_address):
            raise InvalidBinaryAddress("token_address must be a valid address in binary")

        if token_address == NULL_ADDRESS_BYTES:
            raise InvalidTokenAddress("token_address must be non-zero")

        # The following check is on the same chain state as the
        # `chainstate` variable defined below because the chain state does
        # not change between this line and seven lines below.
        # views.state_from_raiden() returns the same state again and again
        # as far as this gevent context is running.
        if token_address in self.get_tokens_list(registry_address):
            raise AlreadyRegisteredTokenAddress("Token already registered")

        chainstate = views.state_from_raiden(self.raiden)

        registry = self.raiden.proxy_manager.token_network_registry(registry_address)

        token_network_address = registry.add_token(
            token_address=token_address,
            channel_participant_deposit_limit=channel_participant_deposit_limit,
            token_network_deposit_limit=token_network_deposit_limit,
            block_identifier=chainstate.block_hash,
        )

        waiting.wait_for_token_network(
            raiden=self.raiden,
            token_network_registry_address=registry_address,
            token_address=token_address,
            retry_timeout=retry_timeout,
        )

        return token_network_address

    def token_network_connect(
        self,
        registry_address: TokenNetworkRegistryAddress,
        token_address: TokenAddress,
        funds: TokenAmount,
        initial_channel_target: int = 3,
        joinable_funds_target: float = 0.4,
    ) -> None:
        """ Automatically maintain channels open for the given token network.

        Args:
            token_address: the ERC20 token network to connect to.
            funds: the amount of funds that can be used by the ConnectionManager.
            initial_channel_target: number of channels to open proactively.
            joinable_funds_target: fraction of the funds that will be used to join
                channels opened by other participants.
        """
        if not is_binary_address(registry_address):
            raise InvalidBinaryAddress("registry_address must be a valid address in binary")
        if not is_binary_address(token_address):
            raise InvalidBinaryAddress("token_address must be a valid address in binary")

        token_network_address = views.get_token_network_address_by_token_address(
            chain_state=views.state_from_raiden(self.raiden),
            token_network_registry_address=registry_address,
            token_address=token_address,
        )

        if token_network_address is None:
            raise UnknownTokenAddress(
                f"Token {to_checksum_address(token_address)} is not registered "
                f"with the network {to_checksum_address(registry_address)}."
            )

        connection_manager = self.raiden.connection_manager_for_token_network(
            token_network_address
        )

        has_enough_reserve, estimated_required_reserve = has_enough_gas_reserve(
            raiden=self.raiden, channels_to_open=initial_channel_target
        )

        if not has_enough_reserve:
            raise InsufficientGasReserve(
                "The account balance is below the estimated amount necessary to "
                "finish the lifecycles of all active channels. A balance of at "
                f"least {estimated_required_reserve} wei is required."
            )

        connection_manager.connect(
            funds=funds,
            initial_channel_target=initial_channel_target,
            joinable_funds_target=joinable_funds_target,
        )

    def token_network_leave(
        self, registry_address: TokenNetworkRegistryAddress, token_address: TokenAddress
    ) -> List[NettingChannelState]:
        """ Close all channels and wait for settlement. """
        if not is_binary_address(registry_address):
            raise InvalidBinaryAddress("registry_address must be a valid address in binary")
        if not is_binary_address(token_address):
            raise InvalidBinaryAddress("token_address must be a valid address in binary")

        token_network_address = views.get_token_network_address_by_token_address(
            chain_state=views.state_from_raiden(self.raiden),
            token_network_registry_address=registry_address,
            token_address=token_address,
        )

        if token_network_address is None:
            raise UnknownTokenAddress(
                f"Token {to_checksum_address(token_address)} is not registered "
                f"with the network {to_checksum_address(registry_address)}."
            )

        connection_manager = self.raiden.connection_manager_for_token_network(
            token_network_address
        )

        return connection_manager.leave(registry_address)

    def is_already_existing_channel(
        self,
        token_network_address: TokenNetworkAddress,
        partner_address: Address,
        block_identifier: Optional[BlockSpecification] = None,
    ) -> bool:
        proxy_manager = self.raiden.proxy_manager
        proxy = proxy_manager.address_to_token_network[token_network_address]
        channel_identifier = proxy.get_channel_identifier_or_none(
            participant1=self.raiden.address,
            participant2=partner_address,
            block_identifier=block_identifier or proxy_manager.client.get_checking_block(),
        )

        return channel_identifier is not None

    def channel_open(
        self,
        registry_address: TokenNetworkRegistryAddress,
        token_address: TokenAddress,
        partner_address: Address,
        settle_timeout: BlockTimeout = None,
        reveal_timeout: BlockTimeout = None,
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ) -> ChannelID:
        """ Open a channel with the peer at `partner_address`
        with the given `token_address`.
        """
        if settle_timeout is None:
            settle_timeout = self.raiden.config["settle_timeout"]

        if reveal_timeout is None:
            reveal_timeout = self.raiden.config["reveal_timeout"]

        if reveal_timeout <= 0:
            raise InvalidRevealTimeout("reveal_timeout should be larger than zero")

        if settle_timeout < reveal_timeout * 2:
            raise InvalidSettleTimeout(
                "`settle_timeout` can not be smaller than double the "
                "`reveal_timeout`.\n "
                "\n "
                "The setting `reveal_timeout` determines the maximum number of "
                "blocks it should take a transaction to be mined when the "
                "blockchain is under congestion. This setting determines the "
                "when a node must go on-chain to register a secret, and it is "
                "therefore the lower bound of the lock expiration. The "
                "`settle_timeout` determines when a channel can be settled "
                "on-chain, for this operation to be safe all locks must have "
                "been resolved, for this reason the `settle_timeout` has to be "
                "larger than `reveal_timeout`."
            )

        if not is_binary_address(registry_address):
            raise InvalidBinaryAddress(
                "Expected binary address format for registry in channel open"
            )

        if not is_binary_address(token_address):
            raise InvalidBinaryAddress("Expected binary address format for token in channel open")

        if not is_binary_address(partner_address):
            raise InvalidBinaryAddress(
                "Expected binary address format for partner in channel open"
            )

        confirmed_block_identifier = views.state_from_raiden(self.raiden).block_hash
        registry = self.raiden.proxy_manager.token_network_registry(registry_address)

        settlement_timeout_min = registry.settlement_timeout_min(
            block_identifier=confirmed_block_identifier
        )
        settlement_timeout_max = registry.settlement_timeout_max(
            block_identifier=confirmed_block_identifier
        )

        if settle_timeout < settlement_timeout_min:
            raise InvalidSettleTimeout(
                f"Settlement timeout should be at least {settlement_timeout_min}"
            )

        if settle_timeout > settlement_timeout_max:
            raise InvalidSettleTimeout(
                f"Settlement timeout exceeds max of {settlement_timeout_max}"
            )

        token_network_address = registry.get_token_network(
            token_address=token_address, block_identifier=confirmed_block_identifier
        )
        if token_network_address is None:
            raise TokenNotRegistered(
                "Token network for token %s does not exist" % to_checksum_address(token_address)
            )

        token_network = self.raiden.proxy_manager.token_network(token_network_address)

        safety_deprecation_switch = token_network.safety_deprecation_switch(
            block_identifier=confirmed_block_identifier
        )

        if safety_deprecation_switch:
            msg = (
                "This token_network has been deprecated. New channels cannot be "
                "open for this network, usage of the newly deployed token "
                "network contract is highly encouraged."
            )
            raise TokenNetworkDeprecated(msg)

        duplicated_channel = self.is_already_existing_channel(
            token_network_address=token_network_address,
            partner_address=partner_address,
            block_identifier=confirmed_block_identifier,
        )
        if duplicated_channel:
            raise DuplicatedChannelError(
                f"A channel with {to_checksum_address(partner_address)} for token "
                f"{to_checksum_address(token_address)} already exists. "
                f"(At blockhash: {confirmed_block_identifier.hex()})"
            )

        with self.raiden.gas_reserve_lock:
            has_enough_reserve, estimated_required_reserve = has_enough_gas_reserve(
                self.raiden, channels_to_open=1
            )

            if not has_enough_reserve:
                raise InsufficientGasReserve(
                    "The account balance is below the estimated amount necessary to "
                    "finish the lifecycles of all active channels. A balance of at "
                    f"least {estimated_required_reserve} wei is required."
                )

            try:
                token_network.new_netting_channel(
                    partner=partner_address,
                    settle_timeout=settle_timeout,
                    given_block_identifier=confirmed_block_identifier,
                )
            except DuplicatedChannelError:
                log.info("partner opened channel first")
            except RaidenRecoverableError:
                # The channel may have been created in the pending block.
                duplicated_channel = self.is_already_existing_channel(
                    token_network_address=token_network_address, partner_address=partner_address
                )
                if duplicated_channel:
                    log.info("Channel has already been opened")
                else:
                    raise

        waiting.wait_for_newchannel(
            raiden=self.raiden,
            token_network_registry_address=registry_address,
            token_address=token_address,
            partner_address=partner_address,
            retry_timeout=retry_timeout,
        )

        chain_state = views.state_from_raiden(self.raiden)
        channel_state = views.get_channelstate_for(
            chain_state=chain_state,
            token_network_registry_address=registry_address,
            token_address=token_address,
            partner_address=partner_address,
        )

        assert channel_state, f"channel {channel_state} is gone"

        self.raiden.set_channel_reveal_timeout(
            canonical_identifier=channel_state.canonical_identifier, reveal_timeout=reveal_timeout
        )

        return channel_state.identifier

    def mint_token(
        self,
        token_address: TokenAddress,
        to: Address,
        value: TokenAmount,
        contract_method: MintingMethod,
    ) -> TransactionHash:
        """ Try to mint `value` units of the token at `token_address` and assign them to `to`,
        using the minting method named `contract_method`.

        Raises:
            MintFailed if the minting fails for any reason.
        """
        jsonrpc_client = self.raiden.rpc_client
        token_proxy = token_minting_proxy(jsonrpc_client, token_address)
        args = [to, value] if contract_method == MintingMethod.MINT else [value, to]

        return call_minting_method(jsonrpc_client, token_proxy, contract_method, args)

    def set_total_channel_withdraw(
        self,
        registry_address: TokenNetworkRegistryAddress,
        token_address: TokenAddress,
        partner_address: Address,
        total_withdraw: WithdrawAmount,
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ) -> None:
        """ Set the `total_withdraw` in the channel with the peer at `partner_address` and the
        given `token_address`.

        Raises:
            InvalidBinaryAddress: If either token_address or partner_address is not
                20 bytes long.
            RaidenUnrecoverableError: May happen for multiple reasons:
                - During preconditions checks, if the channel was not open
                  at the time of the set_total_deposit call.
                - If the transaction fails during gas estimation or
                  if a previous withdraw transaction with the same value
                   was already mined.
            DepositMismatch: The total withdraw amount did not increase.
        """
        chain_state = views.state_from_raiden(self.raiden)

        token_addresses = views.get_token_identifiers(chain_state, registry_address)
        channel_state = views.get_channelstate_for(
            chain_state=chain_state,
            token_network_registry_address=registry_address,
            token_address=token_address,
            partner_address=partner_address,
        )

        if not is_binary_address(token_address):
            raise InvalidBinaryAddress(
                "Expected binary address format for token in channel deposit"
            )

        if not is_binary_address(partner_address):
            raise InvalidBinaryAddress(
                "Expected binary address format for partner in channel deposit"
            )

        if token_address not in token_addresses:
            raise UnknownTokenAddress("Unknown token address")

        if channel_state is None:
            raise NonexistingChannel("No channel with partner_address for the given token")

        if total_withdraw <= channel_state.our_total_withdraw:
            raise WithdrawMismatch(f"Total withdraw {total_withdraw} did not increase")

        current_balance = channel.get_balance(
            sender=channel_state.our_state, receiver=channel_state.partner_state
        )
        amount_to_withdraw = total_withdraw - channel_state.our_total_withdraw
        if amount_to_withdraw > current_balance:
            raise InsufficientFunds(
                "The withdraw of {} is bigger than the current balance of {}".format(
                    amount_to_withdraw, current_balance
                )
            )

        self.raiden.withdraw(
            canonical_identifier=channel_state.canonical_identifier, total_withdraw=total_withdraw
        )

        waiting.wait_for_withdraw_complete(
            raiden=self.raiden,
            canonical_identifier=channel_state.canonical_identifier,
            total_withdraw=total_withdraw,
            retry_timeout=retry_timeout,
        )

    def set_total_channel_deposit(
        self,
        registry_address: TokenNetworkRegistryAddress,
        token_address: TokenAddress,
        partner_address: Address,
        total_deposit: TokenAmount,
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ) -> None:
        """ Set the `total_deposit` in the channel with the peer at `partner_address` and the
        given `token_address` in order to be able to do transfers.

        Raises:
            InvalidBinaryAddress: If either token_address or partner_address is not
                20 bytes long.
            RaidenRecoverableError: May happen for multiple reasons:
                - If the token approval fails, e.g. the token may validate if
                account has enough balance for the allowance.
                - The deposit failed, e.g. the allowance did not set the token
                aside for use and the user spent it before deposit was called.
                - The channel was closed/settled between the allowance call and
                the deposit call.
            AddressWithoutCode: The channel was settled during the deposit
                execution.
            DepositOverLimit: The total deposit amount is higher than the limit.
            UnexpectedChannelState: The channel is no longer in an open state.
        """
        chain_state = views.state_from_raiden(self.raiden)

        token_addresses = views.get_token_identifiers(chain_state, registry_address)
        channel_state = views.get_channelstate_for(
            chain_state=chain_state,
            token_network_registry_address=registry_address,
            token_address=token_address,
            partner_address=partner_address,
        )

        if not is_binary_address(token_address):
            raise InvalidBinaryAddress(
                "Expected binary address format for token in channel deposit"
            )

        if not is_binary_address(partner_address):
            raise InvalidBinaryAddress(
                "Expected binary address format for partner in channel deposit"
            )

        if token_address not in token_addresses:
            raise UnknownTokenAddress("Unknown token address")

        if channel_state is None:
            raise NonexistingChannel("No channel with partner_address for the given token")

        token = self.raiden.proxy_manager.token(token_address)
        token_network_registry = self.raiden.proxy_manager.token_network_registry(registry_address)
        confirmed_block_identifier = views.state_from_raiden(self.raiden).block_hash
        token_network_address = token_network_registry.get_token_network(
            token_address=token_address, block_identifier=confirmed_block_identifier
        )

        if token_network_address is None:
            raise UnknownTokenAddress(
                f"Token {to_checksum_address(token_address)} is not registered "
                f"with the network {to_checksum_address(registry_address)}."
            )

        token_network_proxy = self.raiden.proxy_manager.token_network(token_network_address)
        channel_proxy = self.raiden.proxy_manager.payment_channel(
            canonical_identifier=channel_state.canonical_identifier
        )

        blockhash = chain_state.block_hash
        token_network_proxy = channel_proxy.token_network

        safety_deprecation_switch = token_network_proxy.safety_deprecation_switch(
            block_identifier=blockhash
        )

        balance = token.balance_of(self.raiden.address, block_identifier=blockhash)

        network_balance = token.balance_of(
            address=Address(token_network_address), block_identifier=blockhash
        )
        token_network_deposit_limit = token_network_proxy.token_network_deposit_limit(
            block_identifier=blockhash
        )

        addendum = total_deposit - channel_state.our_state.contract_balance

        channel_participant_deposit_limit = token_network_proxy.channel_participant_deposit_limit(
            block_identifier=blockhash
        )
        total_channel_deposit = total_deposit + channel_state.partner_state.contract_balance

        is_channel_open = channel.get_status(channel_state) == ChannelState.STATE_OPENED

        if not is_channel_open:
            raise UnexpectedChannelState("Channel is not in an open state.")

        if safety_deprecation_switch:
            msg = (
                "This token_network has been deprecated. "
                "All channels in this network should be closed and "
                "the usage of the newly deployed token network contract "
                "is highly encouraged."
            )
            raise TokenNetworkDeprecated(msg)

        if total_deposit <= channel_state.our_state.contract_balance:
            raise DepositMismatch("Total deposit did not increase.")

        # If this check succeeds it does not imply the the `deposit` will
        # succeed, since the `deposit` transaction may race with another
        # transaction.
        if not (balance >= addendum):
            msg = "Not enough balance to deposit. {} Available={} Needed={}".format(
                to_checksum_address(token_address), balance, addendum
            )
            raise InsufficientFunds(msg)

        if network_balance + addendum > token_network_deposit_limit:
            msg = f"Deposit of {addendum} would have exceeded the token network deposit limit."
            raise DepositOverLimit(msg)

        if total_deposit > channel_participant_deposit_limit:
            msg = (
                f"Deposit of {total_deposit} is larger than the "
                f"channel participant deposit limit"
            )
            raise DepositOverLimit(msg)

        if total_channel_deposit >= UINT256_MAX:
            raise DepositOverLimit("Deposit overflow")

        # set_total_deposit calls approve
        # token.approve(netcontract_address, addendum)
        try:
            channel_proxy.set_total_deposit(
                total_deposit=total_deposit, block_identifier=blockhash
            )
        except RaidenRecoverableError as e:
            log.info(f"Deposit failed. {str(e)}")

        target_address = self.raiden.address
        waiting.wait_for_participant_deposit(
            raiden=self.raiden,
            token_network_registry_address=registry_address,
            token_address=token_address,
            partner_address=partner_address,
            target_address=target_address,
            target_balance=total_deposit,
            retry_timeout=retry_timeout,
        )

    def set_reveal_timeout(
        self,
        registry_address: TokenNetworkRegistryAddress,
        token_address: TokenAddress,
        partner_address: Address,
        reveal_timeout: BlockTimeout,
    ) -> None:
        """ Set the `reveal_timeout` in the channel with the peer at `partner_address` and the
        given `token_address`.

        Raises:
            InvalidBinaryAddress: If either token_address or partner_address is not
                20 bytes long.
            InvalidRevealTimeout: If reveal_timeout has an invalid value.
        """
        chain_state = views.state_from_raiden(self.raiden)

        token_addresses = views.get_token_identifiers(chain_state, registry_address)
        channel_state = views.get_channelstate_for(
            chain_state=chain_state,
            token_network_registry_address=registry_address,
            token_address=token_address,
            partner_address=partner_address,
        )

        if not is_binary_address(token_address):
            raise InvalidBinaryAddress(
                "Expected binary address format for token in channel deposit"
            )

        if not is_binary_address(partner_address):
            raise InvalidBinaryAddress(
                "Expected binary address format for partner in channel deposit"
            )

        if token_address not in token_addresses:
            raise UnknownTokenAddress("Unknown token address")

        if channel_state is None:
            raise NonexistingChannel("No channel with partner_address for the given token")

        if reveal_timeout <= 0:
            raise InvalidRevealTimeout("reveal_timeout should be larger than zero.")

        if channel_state.settle_timeout < reveal_timeout * 2:
            raise InvalidRevealTimeout(
                "`settle_timeout` should be at least double the " "provided `reveal_timeout`."
            )

        self.raiden.set_channel_reveal_timeout(
            canonical_identifier=channel_state.canonical_identifier, reveal_timeout=reveal_timeout
        )

    def channel_close(
        self,
        registry_address: TokenNetworkRegistryAddress,
        token_address: TokenAddress,
        partner_address: Address,
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ) -> None:
        """Close a channel opened with `partner_address` for the given
        `token_address`.

        Race condition, this can fail if channel was closed externally.
        """
        self.channel_batch_close(
            registry_address=registry_address,
            token_address=token_address,
            partner_addresses=[partner_address],
            retry_timeout=retry_timeout,
        )

    def channel_batch_close(
        self,
        registry_address: TokenNetworkRegistryAddress,
        token_address: TokenAddress,
        partner_addresses: List[Address],
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ) -> None:
        """Close a channel opened with `partner_address` for the given
        `token_address`.

        Race condition, this can fail if channel was closed externally.
        """

        if not is_binary_address(token_address):
            raise InvalidBinaryAddress("Expected binary address format for token in channel close")

        if not all(map(is_binary_address, partner_addresses)):
            raise InvalidBinaryAddress(
                "Expected binary address format for partner in channel close"
            )

        valid_tokens = views.get_token_identifiers(
            chain_state=views.state_from_raiden(self.raiden),
            token_network_registry_address=registry_address,
        )
        if token_address not in valid_tokens:
            raise UnknownTokenAddress("Token address is not known.")

        chain_state = views.state_from_raiden(self.raiden)
        channels_to_close = views.filter_channels_by_partneraddress(
            chain_state=chain_state,
            token_network_registry_address=registry_address,
            token_address=token_address,
            partner_addresses=partner_addresses,
        )

        close_state_changes: List[StateChange] = [
            ActionChannelClose(canonical_identifier=channel_state.canonical_identifier)
            for channel_state in channels_to_close
        ]

        greenlets = set(self.raiden.handle_state_changes(close_state_changes))
        gevent.joinall(greenlets, raise_error=True)

        channel_ids = [channel_state.identifier for channel_state in channels_to_close]

        waiting.wait_for_close(
            raiden=self.raiden,
            token_network_registry_address=registry_address,
            token_address=token_address,
            channel_ids=channel_ids,
            retry_timeout=retry_timeout,
        )

    def get_channel_list(
        self,
        registry_address: TokenNetworkRegistryAddress,
        token_address: TokenAddress = None,
        partner_address: Address = None,
    ) -> List[NettingChannelState]:
        """Returns a list of channels associated with the optionally given
           `token_address` and/or `partner_address`.

        Args:
            token_address: an optionally provided token address
            partner_address: an optionally provided partner address

        Return:
            A list containing all channels the node participates. Optionally
            filtered by a token address and/or partner address.

        Raises:
            KeyError: An error occurred when the token address is unknown to the node.
        """
        if registry_address and not is_binary_address(registry_address):
            raise InvalidBinaryAddress(
                "Expected binary address format for registry in get_channel_list"
            )

        if token_address and not is_binary_address(token_address):
            raise InvalidBinaryAddress(
                "Expected binary address format for token in get_channel_list"
            )

        if partner_address:
            if not is_binary_address(partner_address):
                raise InvalidBinaryAddress(
                    "Expected binary address format for partner in get_channel_list"
                )
            if not token_address:
                raise UnknownTokenAddress("Provided a partner address but no token address")

        if token_address and partner_address:
            channel_state = views.get_channelstate_for(
                chain_state=views.state_from_raiden(self.raiden),
                token_network_registry_address=registry_address,
                token_address=token_address,
                partner_address=partner_address,
            )

            if channel_state:
                result = [channel_state]
            else:
                result = []

        elif token_address:
            result = views.list_channelstate_for_tokennetwork(
                chain_state=views.state_from_raiden(self.raiden),
                token_network_registry_address=registry_address,
                token_address=token_address,
            )

        else:
            result = views.list_all_channelstate(chain_state=views.state_from_raiden(self.raiden))

        return result

    def get_node_network_state(self, node_address: Address) -> NetworkState:
        """ Returns the currently network status of `node_address`. """
        return views.get_node_network_status(
            chain_state=views.state_from_raiden(self.raiden), node_address=node_address
        )

    def start_health_check_for(self, node_address: Address) -> None:
        """ Returns the currently network status of `node_address`. """
        self.raiden.start_health_check_for(node_address)

    def get_tokens_list(self, registry_address: TokenNetworkRegistryAddress) -> List[TokenAddress]:
        """Returns a list of tokens the node knows about"""
        tokens_list = views.get_token_identifiers(
            chain_state=views.state_from_raiden(self.raiden),
            token_network_registry_address=registry_address,
        )
        return tokens_list

    def get_token_network_address_for_token_address(
        self, registry_address: TokenNetworkRegistryAddress, token_address: TokenAddress
    ) -> Optional[TokenNetworkAddress]:
        return views.get_token_network_address_by_token_address(
            chain_state=views.state_from_raiden(self.raiden),
            token_network_registry_address=registry_address,
            token_address=token_address,
        )

    def transfer_and_wait(
        self,
        registry_address: TokenNetworkRegistryAddress,
        token_address: TokenAddress,
        amount: PaymentAmount,
        target: TargetAddress,
        identifier: PaymentID = None,
        transfer_timeout: int = None,
        secret: Secret = None,
        secrethash: SecretHash = None,
        lock_timeout: BlockTimeout = None,
    ) -> "PaymentStatus":
        """ Do a transfer with `target` with the given `amount` of `token_address`. """
        # pylint: disable=too-many-arguments

        payment_status = self.transfer_async(
            registry_address=registry_address,
            token_address=token_address,
            amount=amount,
            target=target,
            identifier=identifier,
            secret=secret,
            secrethash=secrethash,
            lock_timeout=lock_timeout,
        )
        payment_status.payment_done.wait(timeout=transfer_timeout)
        return payment_status

    def transfer_async(
        self,
        registry_address: TokenNetworkRegistryAddress,
        token_address: TokenAddress,
        amount: PaymentAmount,
        target: TargetAddress,
        identifier: PaymentID = None,
        secret: Secret = None,
        secrethash: SecretHash = None,
        lock_timeout: BlockTimeout = None,
    ) -> "PaymentStatus":
        current_state = views.state_from_raiden(self.raiden)
        token_network_registry_address = self.raiden.default_registry.address

        if not isinstance(amount, int):  # pragma: no unittest
            raise InvalidAmount("Amount not a number")

        if amount <= 0:
            raise InvalidAmount("Amount negative")

        if amount > UINT256_MAX:
            raise InvalidAmount("Amount too large")

        if not is_binary_address(token_address):
            raise InvalidBinaryAddress("token address is not valid.")

        if token_address not in views.get_token_identifiers(current_state, registry_address):
            raise UnknownTokenAddress("Token address is not known.")

        if not is_binary_address(target):
            raise InvalidBinaryAddress("target address is not valid.")

        valid_tokens = views.get_token_identifiers(
            views.state_from_raiden(self.raiden), registry_address
        )
        if token_address not in valid_tokens:
            raise UnknownTokenAddress("Token address is not known.")

        if secret is not None and not isinstance(secret, T_Secret):
            raise InvalidSecret("secret is not valid.")

        if secrethash is not None and not isinstance(secrethash, T_SecretHash):
            raise InvalidSecretHash("secrethash is not valid.")

        if identifier is None:
            identifier = create_default_identifier()

        log.debug(
            "Initiating transfer",
            initiator=to_checksum_address(self.raiden.address),
            target=to_checksum_address(target),
            token=to_checksum_address(token_address),
            amount=amount,
            identifier=identifier,
        )

        token_network_address = views.get_token_network_address_by_token_address(
            chain_state=current_state,
            token_network_registry_address=token_network_registry_address,
            token_address=token_address,
        )

        if token_network_address is None:
            raise UnknownTokenAddress(
                f"Token {to_checksum_address(token_address)} is not registered "
                f"with the network {to_checksum_address(registry_address)}."
            )

        payment_status = self.raiden.mediated_transfer_async(
            token_network_address=token_network_address,
            amount=amount,
            target=target,
            identifier=identifier,
            secret=secret,
            secrethash=secrethash,
            lock_timeout=lock_timeout,
        )
        return payment_status

    def get_raiden_events_payment_history_with_timestamps(
        self,
        token_address: TokenAddress = None,
        target_address: Address = None,
        limit: int = None,
        offset: int = None,
    ) -> List[TimestampedEvent]:
        if token_address and not is_binary_address(token_address):
            raise InvalidBinaryAddress(
                "Expected binary address format for token in get_raiden_events_payment_history"
            )

        if target_address and not is_binary_address(target_address):
            raise InvalidBinaryAddress(
                "Expected binary address format for "
                "target_address in get_raiden_events_payment_history"
            )

        assert self.raiden.wal, "Raiden service has to be started for the API to be usable."
        events = self.raiden.wal.storage.get_events_with_timestamps(
            limit=limit,
            offset=offset,
            filters=[
                ("_type", "raiden.transfer.events.EventPaymentReceivedSuccess"),
                ("_type", "raiden.transfer.events.EventPaymentSentFailed"),
                ("_type", "raiden.transfer.events.EventPaymentSentSuccess"),
            ],
            logical_and=False,
        )

        events = [
            e
            for e in events
            if event_filter_for_payments(event=e.wrapped_event, partner_address=target_address)
        ]

        return events

    def get_raiden_events_payment_history(
        self,
        token_address: TokenAddress = None,
        target_address: Address = None,
        limit: int = None,
        offset: int = None,
    ) -> List[Event]:
        timestamped_events = self.get_raiden_events_payment_history_with_timestamps(
            token_address=token_address, target_address=target_address, limit=limit, offset=offset
        )

        return [event.wrapped_event for event in timestamped_events]

    def get_raiden_internal_events_with_timestamps(
        self, limit: int = None, offset: int = None
    ) -> List[TimestampedEvent]:
        assert self.raiden.wal, "Raiden service has to be started for the API to be usable."
        return self.raiden.wal.storage.get_events_with_timestamps(limit=limit, offset=offset)

    transfer = transfer_and_wait

    def get_blockchain_events_network(
        self,
        registry_address: TokenNetworkRegistryAddress,
        from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
        to_block: BlockSpecification = "latest",
    ) -> List[Dict]:
        events = blockchain_events.get_token_network_registry_events(
            proxy_manager=self.raiden.proxy_manager,
            token_network_registry_address=registry_address,
            contract_manager=self.raiden.contract_manager,
            events=blockchain_events.ALL_EVENTS,
            from_block=from_block,
            to_block=to_block,
        )

        return sorted(events, key=lambda evt: evt.get("block_number"), reverse=True)

    def get_blockchain_events_token_network(
        self,
        token_address: TokenAddress,
        from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
        to_block: BlockSpecification = "latest",
    ) -> List[Dict]:
        """Returns a list of blockchain events corresponding to the token_address."""

        if not is_binary_address(token_address):
            raise InvalidBinaryAddress(
                "Expected binary address format for token in get_blockchain_events_token_network"
            )

        confirmed_block_identifier = views.state_from_raiden(self.raiden).block_hash
        token_network_address = self.raiden.default_registry.get_token_network(
            token_address=token_address, block_identifier=confirmed_block_identifier
        )

        if token_network_address is None:
            raise UnknownTokenAddress("Token address is not known.")

        returned_events = blockchain_events.get_token_network_events(
            proxy_manager=self.raiden.proxy_manager,
            token_network_address=token_network_address,
            contract_manager=self.raiden.contract_manager,
            events=blockchain_events.ALL_EVENTS,
            from_block=from_block,
            to_block=to_block,
        )

        for event in returned_events:
            if event.get("args"):
                event["args"] = dict(event["args"])

        returned_events.sort(key=lambda evt: evt.get("block_number"), reverse=True)
        return returned_events

    def get_blockchain_events_channel(
        self,
        token_address: TokenAddress,
        partner_address: Address = None,
        from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
        to_block: BlockSpecification = "latest",
    ) -> List[Dict]:
        if not is_binary_address(token_address):
            raise InvalidBinaryAddress(
                "Expected binary address format for token in get_blockchain_events_channel"
            )
        confirmed_block_identifier = views.state_from_raiden(self.raiden).block_hash
        token_network_address = self.raiden.default_registry.get_token_network(
            token_address=token_address, block_identifier=confirmed_block_identifier
        )
        if token_network_address is None:
            raise UnknownTokenAddress("Token address is not known.")

        channel_list = self.get_channel_list(
            registry_address=self.raiden.default_registry.address,
            token_address=token_address,
            partner_address=partner_address,
        )
        returned_events = []
        for channel_state in channel_list:
            returned_events.extend(
                blockchain_events.get_all_netting_channel_events(
                    proxy_manager=self.raiden.proxy_manager,
                    token_network_address=token_network_address,
                    netting_channel_identifier=channel_state.identifier,
                    contract_manager=self.raiden.contract_manager,
                    from_block=from_block,
                    to_block=to_block,
                )
            )
        returned_events.sort(key=lambda evt: evt.get("block_number"), reverse=True)
        return returned_events

    def create_monitoring_request(
        self, balance_proof: BalanceProofSignedState, reward_amount: TokenAmount
    ) -> Optional[RequestMonitoring]:
        """ This method can be used to create a `RequestMonitoring` message.
        It will contain all data necessary for an external monitoring service to
        - send an updateNonClosingBalanceProof transaction to the TokenNetwork contract,
        for the `balance_proof` that we received from a channel partner.
        - claim the `reward_amount` from the UDC.
        """
        # create RequestMonitoring message from the above + `reward_amount`
        monitor_request = RequestMonitoring.from_balance_proof_signed_state(
            balance_proof=balance_proof,
            non_closing_participant=self.raiden.address,
            reward_amount=reward_amount,
            monitoring_service_contract_address=self.raiden.default_msc_address,
        )
        # sign RequestMonitoring and return
        monitor_request.sign(self.raiden.signer)
        return monitor_request

    def get_pending_transfers(
        self, token_address: TokenAddress = None, partner_address: Address = None
    ) -> List[Dict[str, Any]]:
        chain_state = views.state_from_raiden(self.raiden)
        transfer_tasks = views.get_all_transfer_tasks(chain_state)
        channel_id = None
        confirmed_block_identifier = views.state_from_raiden(self.raiden).block_hash
        if token_address is not None:
            token_network = self.raiden.default_registry.get_token_network(
                token_address=token_address, block_identifier=confirmed_block_identifier
            )
            if token_network is None:
                raise UnknownTokenAddress(f"Token {token_address} not found.")
            if partner_address is not None:
                partner_channel = self.get_channel(
                    registry_address=self.raiden.default_registry.address,
                    token_address=token_address,
                    partner_address=partner_address,
                )
                channel_id = partner_channel.identifier

        return transfer_tasks_view(transfer_tasks, token_address, channel_id)
