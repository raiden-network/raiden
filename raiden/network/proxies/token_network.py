from collections import defaultdict

import structlog
from eth_utils import (
    encode_hex,
    is_binary_address,
    to_canonical_address,
    to_checksum_address,
    to_hex,
    to_normalized_address,
)
from gevent.event import AsyncResult
from gevent.lock import RLock, Semaphore
from web3.exceptions import BadFunctionCallOutput

from raiden.constants import (
    EMPTY_HASH,
    EMPTY_MERKLE_ROOT,
    EMPTY_SIGNATURE,
    GENESIS_BLOCK_NUMBER,
    NULL_ADDRESS_BYTES,
    UINT256_MAX,
    UNLOCK_TX_GAS_LIMIT,
)
from raiden.exceptions import (
    ChannelOutdatedError,
    DepositMismatch,
    DuplicatedChannelError,
    InvalidAddress,
    InvalidChannelID,
    InvalidSettleTimeout,
    NoStateForBlockIdentifier,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
    SamePeerAddress,
    WithdrawMismatch,
)
from raiden.network.proxies.token import Token
from raiden.network.proxies.utils import compare_contract_versions, log_transaction
from raiden.network.rpc.client import StatelessFilter, check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.transfer.balance_proof import pack_balance_proof, pack_balance_proof_update
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.merkle_tree import compute_layers, merkleroot
from raiden.transfer.state import MerkleTreeState
from raiden.utils import pex, safe_gas_limit
from raiden.utils.signer import recover
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    Any,
    BalanceHash,
    BlockNumber,
    BlockSpecification,
    ChainID,
    ChannelID,
    Dict,
    ErrorType,
    Keccak256,
    List,
    Locksroot,
    MerkleTreeLeaves,
    NamedTuple,
    Nonce,
    NoReturn,
    Signature,
    T_BlockHash,
    T_ChannelID,
    T_ChannelState,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    Tuple,
    cast,
    typecheck,
)
from raiden_contracts.constants import (
    CONTRACT_TOKEN_NETWORK,
    GAS_REQUIRED_FOR_CLOSE_CHANNEL,
    GAS_REQUIRED_FOR_OPEN_CHANNEL,
    GAS_REQUIRED_FOR_SET_TOTAL_DEPOSIT,
    GAS_REQUIRED_FOR_SET_TOTAL_WITHDRAW,
    GAS_REQUIRED_FOR_SETTLE_CHANNEL,
    GAS_REQUIRED_FOR_UPDATE_BALANCE_PROOF,
    ChannelInfoIndex,
    ChannelState,
    ParticipantInfoIndex,
)
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)


def raise_on_call_returned_empty(given_block_identifier: BlockSpecification) -> NoReturn:
    """Format a message and raise RaidenUnrecoverableError."""
    # We know that the given address has code because this is checked
    # in the constructor
    if isinstance(given_block_identifier, T_BlockHash):
        given_block_identifier = to_hex(given_block_identifier)

    msg = (
        f"Either the given address is for a different smart contract, "
        f"or the contract was not yet deployed at the block "
        f"{given_block_identifier}. Either way this call should never "
        f"happened."
    )
    raise RaidenUnrecoverableError(msg)


def raise_if_invalid_address_pair(address1: Address, address2: Address) -> None:
    if NULL_ADDRESS_BYTES in (address1, address2):
        raise InvalidAddress("The null address is not allowed as a channel participant.")

    if address1 == address2:
        raise SamePeerAddress("Using the same address for both participants is forbiden.")

    if not (is_binary_address(address1) and is_binary_address(address2)):
        raise InvalidAddress("Addresses must be in binary")


class ChannelData(NamedTuple):
    channel_identifier: ChannelID
    settle_block_number: BlockNumber
    state: ChannelState


class ParticipantDetails(NamedTuple):
    address: Address
    deposit: TokenAmount
    withdrawn: TokenAmount
    is_closer: bool
    balance_hash: BalanceHash
    nonce: Nonce
    locksroot: Locksroot
    locked_amount: TokenAmount


class ParticipantsDetails(NamedTuple):
    our_details: ParticipantDetails
    partner_details: ParticipantDetails


class ChannelDetails(NamedTuple):
    chain_id: ChainID
    channel_data: ChannelData
    participants_data: ParticipantsDetails


class TokenNetwork:
    def __init__(
        self,
        jsonrpc_client,
        token_network_address: TokenNetworkAddress,
        contract_manager: ContractManager,
    ):
        if not is_binary_address(token_network_address):
            raise InvalidAddress("Expected binary address format for token nework")

        check_address_has_code(
            jsonrpc_client, Address(token_network_address), CONTRACT_TOKEN_NETWORK
        )

        self.contract_manager = contract_manager
        proxy = jsonrpc_client.new_contract_proxy(
            self.contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
            to_normalized_address(token_network_address),
        )

        compare_contract_versions(
            proxy=proxy,
            expected_version=contract_manager.contracts_version,
            contract_name=CONTRACT_TOKEN_NETWORK,
            address=Address(token_network_address),
        )

        self.address = token_network_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.node_address = self.client.address
        self.open_channel_transactions: Dict[Address, AsyncResult] = dict()

        # Forbids concurrent operations on the same channel
        self.channel_operations_lock: Dict[Address, RLock] = defaultdict(RLock)

        # Serialize concurent deposits/withdraw on this token network. This must be an
        # exclusive lock, since we need to coordinate the approve and
        # setTotalDeposit/setTotalWithdraw calls.
        self.deposit_lock = Semaphore()
        self.withdraw_lock = Semaphore()

    def token_address(self) -> TokenAddress:
        """ Return the token of this manager. """
        return to_canonical_address(self.proxy.contract.functions.token().call())

    def _new_channel_postconditions(self, partner: Address, block: BlockSpecification):
        channel_created = self._channel_exists_and_not_settled(
            participant1=self.node_address, participant2=partner, block_identifier=block
        )
        if channel_created:
            raise DuplicatedChannelError("Channel with given partner address already exists")

    def new_netting_channel(
        self, partner: Address, settle_timeout: int, given_block_identifier: BlockSpecification
    ) -> ChannelID:
        """ Creates a new channel in the TokenNetwork contract.

        Args:
            partner: The peer to open the channel with.
            settle_timeout: The settle timeout to use for this channel.
            given_block_identifier: The block identifier of the state change that
                                    prompted this proxy action

        Returns:
            The ChannelID of the new netting channel.
        """
        checking_block = self.client.get_checking_block()
        raise_if_invalid_address_pair(self.node_address, partner)

        timeout_min = self.settlement_timeout_min()
        timeout_max = self.settlement_timeout_max()
        invalid_timeout = settle_timeout < timeout_min or settle_timeout > timeout_max
        if invalid_timeout:
            msg = (
                f"settle_timeout must be in range [{timeout_min}, "
                f"{timeout_max}], is {settle_timeout}"
            )
            raise InvalidSettleTimeout(msg)

        if not self.client.can_query_state_for_block(given_block_identifier):
            raise NoStateForBlockIdentifier(
                "Tried to open a channel with a block identifier older than "
                "the pruning limit. This should not happen."
            )

        channel_exists = self._channel_exists_and_not_settled(
            participant1=self.node_address,
            participant2=partner,
            block_identifier=given_block_identifier,
        )
        if channel_exists:
            raise DuplicatedChannelError("Channel with given partner address already exists")

        # Prevent concurrent attempts to open a channel with the same token and
        # partner address.
        if partner not in self.open_channel_transactions:
            new_open_channel_transaction = AsyncResult()
            self.open_channel_transactions[partner] = new_open_channel_transaction

            try:
                log_details = {
                    "node": to_checksum_address(self.node_address),
                    "contract": to_checksum_address(self.address),
                    "peer1": to_checksum_address(self.node_address),
                    "peer2": to_checksum_address(partner),
                    "settle_timeout": settle_timeout,
                }
                with log_transaction(log, "new_netting_channel", log_details):
                    channel_identifier = self._new_netting_channel(
                        partner, settle_timeout, checking_block, log_details
                    )
                    log_details["channel_identifier"] = str(channel_identifier)
            except Exception as e:
                new_open_channel_transaction.set_exception(e)
                raise
            else:
                new_open_channel_transaction.set(channel_identifier)
            finally:
                self.open_channel_transactions.pop(partner, None)
        else:
            # All other concurrent threads should block on the result of opening this channel
            channel_identifier = self.open_channel_transactions[partner].get()

        return channel_identifier

    def _new_netting_channel(
        self,
        partner: Address,
        settle_timeout: int,
        checking_block: BlockSpecification,
        log_details: Dict[Any, Any],
    ) -> ChannelID:
        gas_limit = self.proxy.estimate_gas(
            checking_block,
            "openChannel",
            participant1=self.node_address,
            participant2=partner,
            settle_timeout=settle_timeout,
        )
        if not gas_limit:
            self.proxy.jsonrpc_client.check_for_insufficient_eth(
                transaction_name="openChannel",
                transaction_executed=False,
                required_gas=GAS_REQUIRED_FOR_OPEN_CHANNEL,
                block_identifier=checking_block,
            )
            self._new_channel_postconditions(partner=partner, block=checking_block)

            raise RaidenUnrecoverableError("Creating a new channel will fail")
        else:
            gas_limit = safe_gas_limit(gas_limit, GAS_REQUIRED_FOR_OPEN_CHANNEL)
            log_details["gas_limit"] = gas_limit
            transaction_hash = self.proxy.transact(
                "openChannel",
                gas_limit,
                participant1=self.node_address,
                participant2=partner,
                settle_timeout=settle_timeout,
            )
            self.client.poll(transaction_hash)
            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            if receipt_or_none:
                self._new_channel_postconditions(
                    partner=partner, block=receipt_or_none["blockNumber"]
                )
                raise RaidenUnrecoverableError("creating new channel failed")

        channel_identifier: ChannelID = self._detail_channel(
            participant1=self.node_address, participant2=partner, block_identifier="latest"
        ).channel_identifier

        return channel_identifier

    def get_channel_identifier(
        self, participant1: Address, participant2: Address, block_identifier: BlockSpecification
    ) -> ChannelID:
        """Return the channel identifier for the opened channel among
        `(participant1, participant2)`.

        Raises:
            RaidenRecoverableError: If there is not open channel among
                `(participant1, participant2)`. Note this is the case even if
                there is a channel is a settle state.
            BadFunctionCallOutput: If the `block_identifier` points to a block
                prior to the deployment of the TokenNetwork.
            SamePeerAddress: If an both addresses are equal.
            InvalidAddress: If either of the address is an invalid type or the
                null address.
        """
        raise_if_invalid_address_pair(participant1, participant2)

        channel_identifier = self.proxy.contract.functions.getChannelIdentifier(
            participant=to_checksum_address(participant1),
            partner=to_checksum_address(participant2),
        ).call(block_identifier=block_identifier)

        if channel_identifier == 0:
            msg = (
                f"getChannelIdentifier returned 0, meaning "
                f"no channel currently exists between "
                f"{to_checksum_address(participant1)} and "
                f"{to_checksum_address(participant2)}"
            )
            raise RaidenRecoverableError(msg)

        return channel_identifier

    def _channel_exists_and_not_settled(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockSpecification,
        channel_identifier: ChannelID = None,
    ) -> bool:
        """Returns if the channel exists and is in a non-settled state"""
        try:
            channel_state = self._get_channel_state(
                participant1=participant1,
                participant2=participant2,
                block_identifier=block_identifier,
                channel_identifier=channel_identifier,
            )
        except RaidenRecoverableError:
            return False
        exists_and_not_settled = (
            channel_state > ChannelState.NONEXISTENT and channel_state < ChannelState.SETTLED
        )
        return exists_and_not_settled

    def _detail_participant(
        self,
        channel_identifier: ChannelID,
        detail_for: Address,
        partner: Address,
        block_identifier: BlockSpecification,
    ) -> ParticipantDetails:
        """ Returns a dictionary with the channel participant information. """
        raise_if_invalid_address_pair(detail_for, partner)

        data = self.proxy.contract.functions.getChannelParticipantInfo(
            channel_identifier=channel_identifier,
            participant=to_checksum_address(detail_for),
            partner=to_checksum_address(partner),
        ).call(block_identifier=block_identifier)

        return ParticipantDetails(
            address=detail_for,
            deposit=data[ParticipantInfoIndex.DEPOSIT],
            withdrawn=data[ParticipantInfoIndex.WITHDRAWN],
            is_closer=data[ParticipantInfoIndex.IS_CLOSER],
            balance_hash=data[ParticipantInfoIndex.BALANCE_HASH],
            nonce=data[ParticipantInfoIndex.NONCE],
            locksroot=data[ParticipantInfoIndex.LOCKSROOT],
            locked_amount=data[ParticipantInfoIndex.LOCKED_AMOUNT],
        )

    def _detail_channel(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockSpecification,
        channel_identifier: ChannelID = None,
    ) -> ChannelData:
        """ Returns a ChannelData instance with the channel specific information.

        If no specific channel_identifier is given then it tries to see if there
        is a currently open channel and uses that identifier.

        """
        raise_if_invalid_address_pair(participant1, participant2)

        if channel_identifier is None:
            channel_identifier = self.get_channel_identifier(
                participant1=participant1,
                participant2=participant2,
                block_identifier=block_identifier,
            )
        elif not isinstance(channel_identifier, T_ChannelID):  # pragma: no unittest
            raise InvalidChannelID("channel_identifier must be of type T_ChannelID")
        elif channel_identifier <= 0 or channel_identifier > UINT256_MAX:
            raise InvalidChannelID(
                "channel_identifier must be larger then 0 and smaller then uint256"
            )

        channel_data = self.proxy.contract.functions.getChannelInfo(
            channel_identifier=channel_identifier,
            participant1=to_checksum_address(participant1),
            participant2=to_checksum_address(participant2),
        ).call(block_identifier=block_identifier)

        return ChannelData(
            channel_identifier=channel_identifier,
            settle_block_number=channel_data[ChannelInfoIndex.SETTLE_BLOCK],
            state=channel_data[ChannelInfoIndex.STATE],
        )

    def detail_participants(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockSpecification,
        channel_identifier: ChannelID = None,
    ) -> ParticipantsDetails:
        """ Returns a ParticipantsDetails instance with the participants'
            channel information.

        Note:
            For now one of the participants has to be the node_address
        """
        if self.node_address not in (participant1, participant2):
            raise ValueError("One participant must be the node address")

        if self.node_address == participant2:
            participant1, participant2 = participant2, participant1

        if channel_identifier is None:
            channel_identifier = self.get_channel_identifier(
                participant1=participant1,
                participant2=participant2,
                block_identifier=block_identifier,
            )
        elif not isinstance(channel_identifier, T_ChannelID):  # pragma: no unittest
            raise InvalidChannelID("channel_identifier must be of type T_ChannelID")
        elif channel_identifier <= 0 or channel_identifier > UINT256_MAX:
            raise InvalidChannelID(
                "channel_identifier must be larger then 0 and smaller then uint256"
            )

        our_data = self._detail_participant(
            channel_identifier=channel_identifier,
            detail_for=participant1,
            partner=participant2,
            block_identifier=block_identifier,
        )
        partner_data = self._detail_participant(
            channel_identifier=channel_identifier,
            detail_for=participant2,
            partner=participant1,
            block_identifier=block_identifier,
        )
        return ParticipantsDetails(our_details=our_data, partner_details=partner_data)

    def detail(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockSpecification,
        channel_identifier: ChannelID = None,
    ) -> ChannelDetails:
        """ Returns a ChannelDetails instance with all the details of the
            channel and the channel participants.

        Note:
            For now one of the participants has to be the node_address
        """
        if self.node_address not in (participant1, participant2):
            raise InvalidAddress("One participant must be the node address")

        if self.node_address == participant2:
            participant1, participant2 = participant2, participant1

        channel_data = self._detail_channel(
            participant1=participant1,
            participant2=participant2,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )
        participants_data = self.detail_participants(
            participant1=participant1,
            participant2=participant2,
            block_identifier=block_identifier,
            channel_identifier=channel_data.channel_identifier,
        )
        chain_id = self.proxy.contract.functions.chain_id().call()

        return ChannelDetails(
            chain_id=chain_id, channel_data=channel_data, participants_data=participants_data
        )

    def settlement_timeout_min(self) -> int:
        """ Returns the minimal settlement timeout for the token network. """
        return self.proxy.contract.functions.settlement_timeout_min().call()

    def settlement_timeout_max(self) -> int:
        """ Returns the maximal settlement timeout for the token network. """
        return self.proxy.contract.functions.settlement_timeout_max().call()

    def channel_is_opened(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockSpecification,
        channel_identifier: ChannelID,
    ) -> bool:
        """ Returns true if the channel is in an open state, false otherwise. """
        try:
            channel_state = self._get_channel_state(
                participant1=participant1,
                participant2=participant2,
                block_identifier=block_identifier,
                channel_identifier=channel_identifier,
            )
        except RaidenRecoverableError:
            return False
        return channel_state == ChannelState.OPENED

    def channel_is_closed(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockSpecification,
        channel_identifier: ChannelID,
    ) -> bool:
        """ Returns true if the channel is in a closed state, false otherwise. """
        try:
            channel_state = self._get_channel_state(
                participant1=participant1,
                participant2=participant2,
                block_identifier=block_identifier,
                channel_identifier=channel_identifier,
            )
        except RaidenRecoverableError:
            return False
        return channel_state == ChannelState.CLOSED

    def channel_is_settled(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockSpecification,
        channel_identifier: ChannelID,
    ) -> bool:
        """ Returns true if the channel is in a settled state, false otherwise. """
        try:
            channel_state = self._get_channel_state(
                participant1=participant1,
                participant2=participant2,
                block_identifier=block_identifier,
                channel_identifier=channel_identifier,
            )
        except RaidenRecoverableError:
            return False
        return channel_state >= ChannelState.SETTLED

    def can_transfer(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockSpecification,
        channel_identifier: ChannelID,
    ) -> bool:
        """ Returns True if the channel is opened and the node has deposit in
        it.

        Note: Having a deposit does not imply having a balance for off-chain
        transfers. """
        opened = self.channel_is_opened(
            participant1=participant1,
            participant2=participant2,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )

        if opened is False:
            return False

        deposit = self._detail_participant(
            channel_identifier=channel_identifier,
            detail_for=participant1,
            partner=participant2,
            block_identifier=block_identifier,
        ).deposit
        return deposit > 0

    def _deposit_preconditions(
        self,
        channel_identifier: ChannelID,
        total_deposit: TokenAmount,
        partner: Address,
        token: Token,
        previous_total_deposit: TokenAmount,
        block_identifier: BlockSpecification,
    ) -> None:
        if not self.client.can_query_state_for_block(block_identifier):
            raise NoStateForBlockIdentifier()

        self._check_for_outdated_channel(
            participant1=self.node_address,
            participant2=partner,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )

        amount_to_deposit = total_deposit - previous_total_deposit

        if total_deposit <= previous_total_deposit:
            msg = (
                f"Current total deposit ({previous_total_deposit}) is already larger "
                f"than the requested total deposit amount ({total_deposit})"
            )
            raise DepositMismatch(msg)

        # A node may be setting up multiple channels for the same token
        # concurrently. Because each deposit changes the user balance this
        # check must be serialized with the operation locks.
        #
        # This check is merely informational, used to avoid sending
        # transactions which are known to fail.
        #
        # It is serialized with the deposit_lock to avoid sending invalid
        # transactions on-chain (account without balance). The lock
        # channel_operations_lock is not sufficient, as it allows two
        # concurrent deposits for different channels.
        #
        current_balance = token.balance_of(self.node_address)
        if current_balance < amount_to_deposit:
            msg = (
                f"new_total_deposit - previous_total_deposit =  {amount_to_deposit} can not "
                f"be larger than the available balance {current_balance}, "
                f"for token at address {pex(token.address)}"
            )
            raise DepositMismatch(msg)

    def set_total_deposit(
        self,
        given_block_identifier: BlockSpecification,
        channel_identifier: ChannelID,
        total_deposit: TokenAmount,
        partner: Address,
    ) -> None:
        """ Set channel's total deposit.

        `total_deposit` has to be monotonically increasing, this is enforced by
        the `TokenNetwork` smart contract. This is done for the same reason why
        the balance proofs have a monotonically increasing transferred amount,
        it simplifies the analysis of bad behavior and the handling code of
        out-dated balance proofs.

        Races to `set_total_deposit` are handled by the smart contract, where
        largest total deposit wins. The end balance of the funding accounts is
        undefined. E.g.

        - Acc1 calls set_total_deposit with 10 tokens
        - Acc2 calls set_total_deposit with 13 tokens

        - If Acc2's transaction is mined first, then Acc1 token supply is left intact.
        - If Acc1's transaction is mined first, then Acc2 will only move 3 tokens.

        Races for the same account don't have any unexpeted side-effect.

        Raises:
            DepositMismatch: If the new request total deposit is lower than the
                existing total deposit on-chain for the `given_block_identifier`.
            RaidenRecoverableError: If the channel was closed meanwhile the
                deposit was in transit.
            RaidenUnrecoverableError: If the transaction was sucessful and the
                deposit_amount is not as large as the requested value.
            RuntimeError: If the token address is empty.
            ValueError: If an argument is of the invalid type.
        """
        typecheck(total_deposit, int)

        with self.channel_operations_lock[partner], self.deposit_lock:
            previous_total_deposit = self._detail_participant(
                channel_identifier=channel_identifier,
                detail_for=self.node_address,
                partner=partner,
                block_identifier=given_block_identifier,
            ).deposit

            token_address = self.token_address()
            token = Token(
                jsonrpc_client=self.client,
                token_address=token_address,
                contract_manager=self.contract_manager,
            )
            try:
                self._deposit_preconditions(
                    channel_identifier=channel_identifier,
                    total_deposit=total_deposit,
                    partner=partner,
                    token=token,
                    previous_total_deposit=previous_total_deposit,
                    block_identifier=given_block_identifier,
                )
            except NoStateForBlockIdentifier:
                # If preconditions end up being on pruned state skip them. Estimate
                # gas will stop us from sending a transaction that will fail
                pass

            log_details = {
                "node": to_checksum_address(self.node_address),
                "contract": to_checksum_address(self.address),
                "channel_identifier": channel_identifier,
                "partner": to_checksum_address(partner),
                "new_total_deposit": total_deposit,
                "previous_total_deposit": previous_total_deposit,
            }
            with log_transaction(log, "set_total_deposit", log_details):
                self._set_total_deposit(
                    channel_identifier,
                    total_deposit,
                    partner,
                    previous_total_deposit,
                    token,
                    log_details,
                )

    def _set_total_deposit(
        self,
        channel_identifier: ChannelID,
        total_deposit: TokenAmount,
        partner: Address,
        previous_total_deposit: TokenAmount,
        token: Token,
        log_details: Dict[Any, Any],
    ) -> None:
        checking_block = self.client.get_checking_block()
        error_prefix = "setTotalDeposit call will fail"
        amount_to_deposit = TokenAmount(total_deposit - previous_total_deposit)

        # If there are channels being set up concurrenlty either the
        # allowance must be accumulated *or* the calls to `approve` and
        # `setTotalDeposit` must be serialized. This is necessary otherwise
        # the deposit will fail.
        #
        # Calls to approve and setTotalDeposit are serialized with the
        # deposit_lock to avoid transaction failure, because with two
        # concurrent deposits, we may have the transactions executed in the
        # following order
        #
        # - approve
        # - approve
        # - setTotalDeposit
        # - setTotalDeposit
        #
        # in which case  the second `approve` will overwrite the first,
        # and the first `setTotalDeposit` will consume the allowance,
        # making the second deposit fail.
        token.approve(allowed_address=Address(self.address), allowance=amount_to_deposit)

        gas_limit = self.proxy.estimate_gas(
            checking_block,
            "setTotalDeposit",
            channel_identifier=channel_identifier,
            participant=self.node_address,
            total_deposit=total_deposit,
            partner=partner,
        )

        if gas_limit:
            gas_limit = safe_gas_limit(gas_limit, GAS_REQUIRED_FOR_SET_TOTAL_DEPOSIT)
            error_prefix = "setTotalDeposit call failed"
            log_details["gas_limit"] = gas_limit

            transaction_hash = self.proxy.transact(
                "setTotalDeposit",
                gas_limit,
                channel_identifier=channel_identifier,
                participant=self.node_address,
                total_deposit=total_deposit,
                partner=partner,
            )
            self.client.poll(transaction_hash)
            receipt_or_none = check_transaction_threw(self.client, transaction_hash)

        transaction_executed = gas_limit is not None
        if not transaction_executed or receipt_or_none:
            if transaction_executed:
                block = receipt_or_none["blockNumber"]
            else:
                block = checking_block

            self.proxy.jsonrpc_client.check_for_insufficient_eth(
                transaction_name="setTotalDeposit",
                transaction_executed=transaction_executed,
                required_gas=GAS_REQUIRED_FOR_SET_TOTAL_DEPOSIT,
                block_identifier=block,
            )
            error_type, msg = self._check_why_deposit_failed(
                channel_identifier=channel_identifier,
                partner=partner,
                token=token,
                amount_to_deposit=amount_to_deposit,
                total_deposit=total_deposit,
                transaction_executed=transaction_executed,
                block_identifier=block,
            )

            raise error_type(f"{error_prefix}. {msg}")

    def _check_why_deposit_failed(
        self,
        channel_identifier: ChannelID,
        partner: Address,
        token: Token,
        amount_to_deposit: TokenAmount,
        total_deposit: TokenAmount,
        transaction_executed: bool,
        block_identifier: BlockSpecification,
    ) -> Tuple[ErrorType, str]:
        error_type: ErrorType = RaidenUnrecoverableError
        msg = ""
        latest_deposit = self._detail_participant(
            channel_identifier=channel_identifier,
            detail_for=self.node_address,
            partner=partner,
            block_identifier=block_identifier,
        ).deposit

        allowance = token.allowance(
            owner=self.node_address,
            spender=Address(self.address),
            block_identifier=block_identifier,
        )
        if allowance < amount_to_deposit:
            msg = (
                "The allowance is insufficient. Check concurrent deposits "
                "for the same token network but different proxies."
            )
        elif token.balance_of(self.node_address, block_identifier) < amount_to_deposit:
            msg = "The address doesnt have enough tokens"
        elif transaction_executed and latest_deposit < total_deposit:
            msg = "The tokens were not transferred"
        else:
            participant_details = self.detail_participants(
                participant1=self.node_address,
                participant2=partner,
                block_identifier=block_identifier,
                channel_identifier=channel_identifier,
            )
            channel_state = self._get_channel_state(
                participant1=self.node_address,
                participant2=partner,
                block_identifier=block_identifier,
                channel_identifier=channel_identifier,
            )
            # Check if deposit is being made on a nonexistent channel
            if channel_state in (ChannelState.NONEXISTENT, ChannelState.REMOVED):
                msg = (
                    f"Channel between participant {to_checksum_address(self.node_address)} "
                    f"and {to_checksum_address(partner)} does not exist"
                )
            # Deposit was prohibited because the channel is settled
            elif channel_state == ChannelState.SETTLED:
                msg = "Deposit is not possible due to channel being settled"
            # Deposit was prohibited because the channel is closed
            elif channel_state == ChannelState.CLOSED:
                error_type = RaidenRecoverableError
                msg = "Channel is already closed"
            elif participant_details.our_details.deposit < total_deposit:
                msg = "Deposit amount did not increase after deposit transaction"

        return error_type, msg

    def _withdraw_preconditions(
            self,
            channel_identifier: ChannelID,
            total_withdraw: TokenAmount,
            partner: Address,
            block_identifier: BlockSpecification,
    ) -> Tuple[TokenAmount, Dict]:
        if not isinstance(total_withdraw, int):
            raise ValueError('total_withdraw needs to be an integral number.')

        self._check_for_outdated_channel(
            participant1=self.node_address,
            participant2=partner,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )

        # setTotalWithdraw requires a monotonically increasing value. This
        # is used to handle concurrent actions:
        #
        #  - The withdraws will be done in order, i.e. the monotonic
        #  property is preserved by the caller
        #  - The race of two withdraws will be resolved with the larger
        #  withdraw winning
        #  - Retries wont have effect
        #
        # This check is serialized with the channel_operations_lock to avoid
        # sending invalid transactions on-chain (decreasing total withdraw).
        #
        participant_details = self.detail_participant(
            channel_identifier=channel_identifier,
            participant=self.node_address,
            partner=partner,
            block_identifier=block_identifier,
        )
        previous_total_withdraw = participant_details.withdrawn_amount
        amount_to_withdraw = total_withdraw - previous_total_withdraw

        log_details = {
            'token_network': pex(self.address),
            'channel_identifier': channel_identifier,
            'node': pex(self.node_address),
            'partner': pex(partner),
            'new_total_withdraw': total_withdraw,
            'previous_total_withdraw': previous_total_withdraw,
        }

        # These two scenarios can happen if two calls to withdraw happen
        # and then we get here on the second call
        if total_withdraw < previous_total_withdraw:
            msg = (
                f'Current total withdraw ({previous_total_withdraw}) is already larger '
                f'than the requested total withdraw amount ({total_withdraw})'
            )
            log.info('setTotalWithdraw failed', reason=msg, **log_details)
            raise WithdrawMismatch(msg)

        if amount_to_withdraw <= 0:
            msg = (
                f'new_total_withdraw - previous_total_withdraw must be greater than 0. '
                f'new_total_withdraw={total_withdraw} '
                f'previous_total_withdraw={previous_total_withdraw}'
            )
            log.info('setTotalWithdraw failed', reason=msg, **log_details)
            raise WithdrawMismatch(msg)

        return amount_to_withdraw, log_details

    def set_total_withdraw(
            self,
            given_block_identifier: BlockSpecification,
            channel_identifier: ChannelID,
            total_withdraw: TokenAmount,
            participant_signature: Signature,
            partner_signature: Signature,
            partner: Address,
    ):
        """ Set total token withdraw in the channel to total_withdraw.

        Raises:
            ChannelBusyError: If the channel is busy with another operation
            RuntimeError: If the token address is empty.
        """
        checking_block = self.client.get_checking_block()
        error_prefix = 'setTotalWithdraw call will fail'
        with self.channel_operations_lock[partner], self.withdraw_lock:
            amount_to_withdraw, log_details = self._withdraw_preconditions(
                channel_identifier=channel_identifier,
                total_withdraw=total_withdraw,
                partner=partner,
                block_identifier=given_block_identifier,
            )

            gas_limit = self.proxy.estimate_gas(
                checking_block,
                'setTotalWithdraw',
                channel_identifier,
                self.node_address,
                total_withdraw,
                participant_signature,
                partner_signature,
            )

            if gas_limit:
                gas_limit = safe_gas_limit(gas_limit, GAS_REQUIRED_FOR_SET_TOTAL_WITHDRAW)
                error_prefix = 'setTotalWithdraw call failed'

                log.debug('setTotalWithdraw called', **log_details)
                transaction_hash = self.proxy.transact(
                    'setTotalWithdraw',
                    gas_limit,
                    channel_identifier,
                    self.node_address,
                    total_withdraw,
                    partner,
                )
                self.client.poll(transaction_hash)
                receipt_or_none = check_transaction_threw(self.client, transaction_hash)

            transaction_executed = gas_limit is not None
            if not transaction_executed or receipt_or_none:
                if transaction_executed:
                    block = receipt_or_none['blockNumber']
                else:
                    block = checking_block

                self.proxy.jsonrpc_client.check_for_insufficient_eth(
                    transaction_name='setTotalWithdraw',
                    transaction_executed=transaction_executed,
                    required_gas=GAS_REQUIRED_FOR_SET_TOTAL_WITHDRAW,
                    block_identifier=block,
                )
                error_type, msg = self._check_why_withdraw_failed(
                    channel_identifier=channel_identifier,
                    partner=partner,
                    amount_to_withdraw=amount_to_withdraw,
                    total_withdraw=total_withdraw,
                    transaction_executed=transaction_executed,
                    block_identifier=block,
                )

                error_msg = f'{error_prefix}. {msg}'
                if error_type == RaidenRecoverableError:
                    log.warning(error_msg, **log_details)
                else:
                    log.critical(error_msg, **log_details)
                raise error_type(error_msg)

            log.info('setTotalWithdraw successful', **log_details)

    def close(
        self,
        channel_identifier: ChannelID,
        partner: Address,
        balance_hash: BalanceHash,
        nonce: Nonce,
        additional_hash: AdditionalHash,
        signature: Signature,
        given_block_identifier: BlockSpecification,
    ) -> None:
        """ Close the channel using the provided balance proof.

        Note:
            This method must *not* be called without updating the application
            state, otherwise the node may accept new transfers which cannot be
            used, because the closer is not allowed to update the balance proof
            submitted on chain after closing

        Raises:
            RaidenRecoverableError: If the close call failed but it is not
                critical.
            RaidenUnrecoverableError: If the operation was ilegal at the
                `given_block_identifier` or if the channel changes in a way that
                cannot be recovered.
        """

        if signature != EMPTY_SIGNATURE:
            canonical_identifier = CanonicalIdentifier(
                chain_identifier=self.proxy.contract.functions.chain_id().call(),
                token_network_address=self.address,
                channel_identifier=channel_identifier,
            )
            partner_signed_data = pack_balance_proof(
                nonce=nonce,
                balance_hash=balance_hash,
                additional_hash=additional_hash,
                canonical_identifier=canonical_identifier,
            )
            try:
                partner_recovered_address = recover(data=partner_signed_data, signature=signature)

                # InvalidSignature is raised by raiden.utils.signer.recover if signature
                # is not bytes or has the incorrect length
                #
                # ValueError is raised if the PublicKey instantiation failed, let it
                # propagate because it's a memory pressure problem.
                #
                # Exception is raised if the public key recovery failed.
            except Exception:  # pylint: disable=broad-except
                raise RaidenUnrecoverableError("Couldn't verify the close signature")
            else:
                if partner_recovered_address != partner:
                    raise RaidenUnrecoverableError("Invalid close proof signature")

        try:
            channel_onchain_detail = self._detail_channel(
                participant1=self.node_address,
                participant2=partner,
                block_identifier=given_block_identifier,
                channel_identifier=channel_identifier,
            )
        except ValueError:
            # If `given_block_identifier` has been pruned the checks cannot be
            # performed.
            pass
        except BadFunctionCallOutput:
            raise_on_call_returned_empty(given_block_identifier)
        else:
            onchain_channel_identifier = channel_onchain_detail.channel_identifier
            if onchain_channel_identifier != channel_identifier:
                msg = (
                    f"The provided channel identifier does not match the value "
                    f"on-chain at the provided block ({given_block_identifier}). "
                    f"This call should never have been attempted. "
                    f"provided_channel_identifier={channel_identifier}, "
                    f"onchain_channel_identifier={channel_onchain_detail.channel_identifier}"
                )
                raise RaidenUnrecoverableError(msg)

            if channel_onchain_detail.state != ChannelState.OPENED:
                msg = (
                    f"The channel was not open at the provided block "
                    f"({given_block_identifier}). This call should never have "
                    f"been attempted."
                )
                raise RaidenUnrecoverableError(msg)

        log_details = {
            "node": to_checksum_address(self.node_address),
            "contract": to_checksum_address(self.address),
            "partner": to_checksum_address(partner),
            "nonce": nonce,
            "balance_hash": encode_hex(balance_hash),
            "additional_hash": encode_hex(additional_hash),
            "signature": encode_hex(signature),
        }

        with log_transaction(log, "close", log_details):
            self._close(
                channel_identifier=channel_identifier,
                partner=partner,
                balance_hash=balance_hash,
                nonce=nonce,
                additional_hash=additional_hash,
                signature=signature,
                log_details=log_details,
            )

    def _close(
        self,
        channel_identifier: ChannelID,
        partner: Address,
        balance_hash: BalanceHash,
        nonce: Nonce,
        additional_hash: AdditionalHash,
        signature: Signature,
        log_details: Dict[Any, Any],
    ) -> None:
        with self.channel_operations_lock[partner]:
            checking_block = self.client.get_checking_block()
            gas_limit = self.proxy.estimate_gas(
                checking_block,
                "closeChannel",
                channel_identifier=channel_identifier,
                partner=partner,
                balance_hash=balance_hash,
                nonce=nonce,
                additional_hash=additional_hash,
                signature=signature,
            )

            if gas_limit:
                gas_limit = safe_gas_limit(gas_limit, GAS_REQUIRED_FOR_CLOSE_CHANNEL)
                log_details["gas_limit"] = gas_limit
                transaction_hash = self.proxy.transact(
                    "closeChannel",
                    gas_limit,
                    channel_identifier=channel_identifier,
                    partner=partner,
                    balance_hash=balance_hash,
                    nonce=nonce,
                    additional_hash=additional_hash,
                    signature=signature,
                )
                self.client.poll(transaction_hash)
                receipt_or_none = check_transaction_threw(self.client, transaction_hash)

                if receipt_or_none:
                    # Because the gas estimation succeeded it is known that:
                    # - The channel existed.
                    # - The channel was at the state open.
                    # - The account had enough balance to pay for the gas
                    #   (however there is a race condition for multiple
                    #   transactions #3890)
                    #
                    # So the only reason for the transaction to fail is if our
                    # partner closed it before (assuming exclusive usage of the
                    # account and no compiler bugs)

                    # These checks do not have problems with race conditions because
                    # `poll`ing waits for the transaction to be confirmed.
                    mining_block = int(receipt_or_none["blockNumber"])

                    if receipt_or_none["cumulativeGasUsed"] == gas_limit:
                        msg = (
                            "update transfer failed and all gas was used. Estimate gas "
                            "may have underestimated update transfer, or succeeded even "
                            "though an assert is triggered, or the smart contract code "
                            "has an conditional assert."
                        )
                        raise RaidenUnrecoverableError(msg)

                    partner_details = self._detail_participant(
                        channel_identifier=channel_identifier,
                        detail_for=partner,
                        partner=self.node_address,
                        block_identifier=mining_block,
                    )

                    if partner_details.is_closer:
                        msg = "Channel was already closed by channel partner first."
                        raise RaidenRecoverableError(msg)

                    raise RaidenUnrecoverableError("closeChannel call failed")

            else:
                # The transaction would have failed if sent, figure out why.

                # The latest block can not be used reliably because of reorgs,
                # therefore every call using this block has to handle pruned data.
                failed_at = self.proxy.jsonrpc_client.get_block("latest")
                failed_at_blockhash = encode_hex(failed_at["hash"])
                failed_at_blocknumber = failed_at["number"]

                self.proxy.jsonrpc_client.check_for_insufficient_eth(
                    transaction_name="closeChannel",
                    transaction_executed=True,
                    required_gas=GAS_REQUIRED_FOR_CLOSE_CHANNEL,
                    block_identifier=failed_at_blocknumber,
                )

                detail = self._detail_channel(
                    participant1=self.node_address,
                    participant2=partner,
                    block_identifier=failed_at_blockhash,
                    channel_identifier=channel_identifier,
                )

                if detail.state < ChannelState.OPENED:
                    msg = (
                        f"cannot call close channel has not been opened yet. "
                        f"current_state={detail.state}"
                    )
                    raise RaidenUnrecoverableError(msg)

                if detail.state >= ChannelState.CLOSED:
                    msg = (
                        f"cannot call close on a channel that has been closed already. "
                        f"current_state={detail.state}"
                    )
                    raise RaidenRecoverableError(msg)

                raise RaidenUnrecoverableError("close channel failed for an unknown reason")

    def update_transfer(
        self,
        channel_identifier: ChannelID,
        partner: Address,
        balance_hash: BalanceHash,
        nonce: Nonce,
        additional_hash: AdditionalHash,
        closing_signature: Signature,
        non_closing_signature: Signature,
        given_block_identifier: BlockSpecification,
    ) -> None:
        if balance_hash is EMPTY_HASH:
            raise RaidenUnrecoverableError("update_transfer called with an empty balance_hash")

        if nonce <= 0 or nonce > UINT256_MAX:
            raise RaidenUnrecoverableError("update_transfer called with an invalid nonce")

        canonical_identifier = CanonicalIdentifier(
            chain_identifier=self.proxy.contract.functions.chain_id().call(),
            token_network_address=self.address,
            channel_identifier=channel_identifier,
        )

        partner_signed_data = pack_balance_proof(
            nonce=nonce,
            balance_hash=balance_hash,
            additional_hash=additional_hash,
            canonical_identifier=canonical_identifier,
        )

        our_signed_data = pack_balance_proof_update(
            nonce=nonce,
            balance_hash=balance_hash,
            additional_hash=additional_hash,
            canonical_identifier=canonical_identifier,
            partner_signature=closing_signature,
        )

        try:
            partner_recovered_address = recover(
                data=partner_signed_data, signature=closing_signature
            )

            our_recovered_address = recover(data=our_signed_data, signature=non_closing_signature)

            # InvalidSignature is raised by raiden.utils.signer.recover if signature
            # is not bytes or has the incorrect length
            #
            # ValueError is raised if the PublicKey instantiation failed, let it
            # propagate because it's a memory pressure problem.
            #
            # Exception is raised if the public key recovery failed.
        except Exception:  # pylint: disable=broad-except
            raise RaidenUnrecoverableError("Couldn't verify the balance proof signature")
        else:
            if our_recovered_address != self.node_address:
                raise RaidenUnrecoverableError("Invalid balance proof signature")

            if partner_recovered_address != partner:
                raise RaidenUnrecoverableError("Invalid update transfer signature")

        # Check the preconditions for calling updateNonClosingBalanceProof at
        # the time the event was emitted.
        try:
            channel_onchain_detail = self._detail_channel(
                participant1=self.node_address,
                participant2=partner,
                block_identifier=given_block_identifier,
                channel_identifier=channel_identifier,
            )
            closer_details = self._detail_participant(
                channel_identifier=channel_identifier,
                detail_for=partner,
                partner=self.node_address,
                block_identifier=given_block_identifier,
            )
            given_block_number = self.client.get_block(given_block_identifier)["number"]
        except ValueError:
            # If `given_block_identifier` has been pruned the checks cannot be
            # performed.
            pass
        except BadFunctionCallOutput:
            raise_on_call_returned_empty(given_block_identifier)
        else:
            # The latest channel is of no importance for the update transfer
            # precondition checks, the only constraint that has to be satisfied
            # is that the provided channel id provided is at the correct
            # state. For this reason `getChannelIdentifier` is not called, as
            # for version 0.4.0 that would return the identifier of the latest
            # channel.

            if channel_onchain_detail.state != ChannelState.CLOSED:
                msg = (
                    f"The channel was not closed at the provided block "
                    f"({given_block_identifier}). This call should never have "
                    f"been attempted."
                )
                raise RaidenUnrecoverableError(msg)

            if channel_onchain_detail.settle_block_number < given_block_number:
                msg = (
                    "update transfer cannot be called after the settlement "
                    "period, this call should never have been attempted."
                )
                raise RaidenUnrecoverableError(msg)

            if closer_details.nonce == nonce:
                msg = (
                    "update transfer was already done, this call should never "
                    "have been attempted."
                )
                raise RaidenRecoverableError(msg)

        log_details = {
            "contract": to_checksum_address(self.address),
            "node": to_checksum_address(self.node_address),
            "partner": to_checksum_address(partner),
            "nonce": nonce,
            "balance_hash": encode_hex(balance_hash),
            "additional_hash": encode_hex(additional_hash),
            "closing_signature": encode_hex(closing_signature),
            "non_closing_signature": encode_hex(non_closing_signature),
        }

        with log_transaction(log, "update_transfer", log_details):
            self._update_transfer(
                channel_identifier=channel_identifier,
                partner=partner,
                balance_hash=balance_hash,
                nonce=nonce,
                additional_hash=additional_hash,
                closing_signature=closing_signature,
                non_closing_signature=non_closing_signature,
                log_details=log_details,
            )

    def _update_transfer(
        self,
        channel_identifier: ChannelID,
        partner: Address,
        balance_hash: BalanceHash,
        nonce: Nonce,
        additional_hash: AdditionalHash,
        closing_signature: Signature,
        non_closing_signature: Signature,
        log_details: Dict[Any, Any],
    ) -> None:
        checking_block = self.client.get_checking_block()
        gas_limit = self.proxy.estimate_gas(
            checking_block,
            "updateNonClosingBalanceProof",
            channel_identifier=channel_identifier,
            closing_participant=partner,
            non_closing_participant=self.node_address,
            balance_hash=balance_hash,
            nonce=nonce,
            additional_hash=additional_hash,
            closing_signature=closing_signature,
            non_closing_signature=non_closing_signature,
        )

        if gas_limit:
            gas_limit = safe_gas_limit(gas_limit, GAS_REQUIRED_FOR_UPDATE_BALANCE_PROOF)
            log_details["gas_limit"] = gas_limit
            transaction_hash = self.proxy.transact(
                "updateNonClosingBalanceProof",
                gas_limit,
                channel_identifier=channel_identifier,
                closing_participant=partner,
                non_closing_participant=self.node_address,
                balance_hash=balance_hash,
                nonce=nonce,
                additional_hash=additional_hash,
                closing_signature=closing_signature,
                non_closing_signature=non_closing_signature,
            )

            self.client.poll(transaction_hash)
            receipt_or_none = check_transaction_threw(self.client, transaction_hash)

            if receipt_or_none:
                # Because the gas estimation succeeded it is known that:
                # - The channel existed.
                # - The channel was at the state closed.
                # - The partner node was the closing address.
                # - The account had enough balance to pay for the gas (however
                #   there is a race condition for multiple transactions #3890)

                # These checks do not have problems with race conditions because
                # `poll`ing waits for the transaction to be confirmed.
                mining_block = int(receipt_or_none["blockNumber"])

                if receipt_or_none["cumulativeGasUsed"] == gas_limit:
                    msg = (
                        "update transfer failed and all gas was used. Estimate gas "
                        "may have underestimated update transfer, or succeeded even "
                        "though an assert is triggered, or the smart contract code "
                        "has an conditional assert."
                    )
                    raise RaidenUnrecoverableError(msg)

                # Query the current state to check for transaction races
                channel_data = self._detail_channel(
                    participant1=self.node_address,
                    participant2=partner,
                    block_identifier=mining_block,
                    channel_identifier=channel_identifier,
                )

                # The channel identifier can be set to 0 if the channel is
                # settled, or it could have a higher value if a new channel was
                # opened. A lower value is an unrecoverable error.
                was_channel_gone = (
                    channel_data.channel_identifier == 0
                    or channel_data.channel_identifier > channel_identifier
                )

                if was_channel_gone:
                    msg = (
                        f"The provided channel identifier does not match the value "
                        f"on-chain at the block the update transfer was mined ({mining_block}). "
                        f"provided_channel_identifier={channel_identifier}, "
                        f"onchain_channel_identifier={channel_data.channel_identifier}"
                    )
                    raise RaidenRecoverableError(msg)

                if channel_data.state >= ChannelState.SETTLED:
                    # This should never happen if the settlement window and gas
                    # price estimation is done properly.
                    #
                    # This is a race condition that cannot be prevented,
                    # therefore it is a recoverable error.
                    msg = "Channel was already settled when update transfer was mined."
                    raise RaidenRecoverableError(msg)

                if channel_data.settle_block_number < mining_block:
                    # The channel is cleared from the smart contract's storage
                    # on call to settle, this means that settle_block_number
                    # may be zero, therefore this check must be done after the
                    # channel's state check.
                    #
                    # This is a race condition that cannot be prevented,
                    # therefore it is a recoverable error.
                    msg = "update transfer was mined after the settlement " "window."
                    raise RaidenRecoverableError(msg)

                partner_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=partner,
                    partner=self.node_address,
                    block_identifier=mining_block,
                )
                if partner_details.nonce != nonce:
                    # A higher value should be impossible because a signature
                    # from this node is necessary and this node should send the
                    # partner's balance proof with the highest nonce
                    #
                    # A lower value means some unexpected failure.
                    msg = (
                        f"update transfer failed, the on-chain nonce is higher then our expected "
                        f"value expected={nonce} actual={partner_details.nonce}"
                    )
                    raise RaidenUnrecoverableError(msg)

                if channel_data.state < ChannelState.CLOSED:
                    msg = (
                        f"The channel state changed unexpectedly. "
                        f"block=({mining_block}) onchain_state={channel_data.state}"
                    )
                    raise RaidenUnrecoverableError(msg)

                raise RaidenUnrecoverableError("update transfer failed for an unknown reason")

        else:
            # The transaction would have failed if sent, figure out why.

            # The latest block can not be used reliably because of reorgs,
            # therefore every call using this block has to handle pruned data.
            failed_at = self.proxy.jsonrpc_client.get_block("latest")
            failed_at_blockhash = encode_hex(failed_at["hash"])
            failed_at_blocknumber = failed_at["number"]

            self.proxy.jsonrpc_client.check_for_insufficient_eth(
                transaction_name="updateNonClosingBalanceProof",
                transaction_executed=False,
                required_gas=GAS_REQUIRED_FOR_UPDATE_BALANCE_PROOF,
                block_identifier=failed_at_blocknumber,
            )

            detail = self._detail_channel(
                participant1=self.node_address,
                participant2=partner,
                block_identifier=failed_at_blockhash,
                channel_identifier=channel_identifier,
            )

            if detail.state < ChannelState.CLOSED:
                msg = (
                    f"cannot call update_transfer channel has not been closed yet. "
                    f"current_state={detail.state}"
                )
                raise RaidenUnrecoverableError(msg)

            if detail.state >= ChannelState.SETTLED:
                msg = (
                    f"cannot call update_transfer channel has been settled already. "
                    f"current_state={detail.state}"
                )
                raise RaidenRecoverableError(msg)

            if detail.settle_block_number < failed_at_blocknumber:
                raise RaidenRecoverableError(
                    "update_transfer transation sent after settlement window"
                )

            # At this point it is known the channel is CLOSED on block
            # `failed_at_blockhash`
            partner_details = self._detail_participant(
                channel_identifier=channel_identifier,
                detail_for=partner,
                partner=self.node_address,
                block_identifier=failed_at_blockhash,
            )

            if not partner_details.is_closer:
                raise RaidenUnrecoverableError(
                    "update_transfer cannot be sent if the partner did not close the channel"
                )

            raise RaidenUnrecoverableError("update_transfer failed for an unknown reason")

    def unlock(
        self,
        channel_identifier: ChannelID,
        sender: Address,
        receiver: Address,
        merkle_tree_locks: MerkleTreeLeaves,
        given_block_identifier: BlockSpecification,
    ) -> None:
        if not merkle_tree_locks:
            raise ValueError("unlock cannot be done without merkle_tree_leaves")

        # Check the preconditions for calling unlock at the time the event was
        # emitted.
        try:
            channel_onchain_detail = self._detail_channel(
                participant1=sender,
                participant2=receiver,
                block_identifier=given_block_identifier,
                channel_identifier=channel_identifier,
            )
            sender_details = self._detail_participant(
                channel_identifier=channel_identifier,
                detail_for=sender,
                partner=receiver,
                block_identifier=given_block_identifier,
            )
        except ValueError:
            # If `given_block_identifier` has been pruned the checks cannot be
            # performed.
            pass
        except BadFunctionCallOutput:
            raise_on_call_returned_empty(given_block_identifier)
        else:
            if channel_onchain_detail.state != ChannelState.SETTLED:
                msg = (
                    f"The channel was not settled at the provided block "
                    f"({given_block_identifier}). This call should never have "
                    f"been attempted."
                )
                raise RaidenUnrecoverableError(msg)

            leaves = cast(List[Keccak256], [lock.lockhash for lock in merkle_tree_locks])
            merkle_tree = MerkleTreeState(compute_layers(leaves))
            local_merkleroot = merkleroot(merkle_tree)
            if sender_details.locksroot != local_merkleroot:
                msg = (
                    f"The provided merkle tree ({to_hex(local_merkleroot)}) "
                    f"does correspond to the on-chain locksroot "
                    f"{to_hex(sender_details.locksroot)} for sender "
                    f"{to_checksum_address(sender)}."
                )
                raise RaidenUnrecoverableError(msg)

            if sender_details.locked_amount == 0:
                msg = (
                    f"The provided locked amount on-chain is 0. This should "
                    f"never happen because a lock with an amount 0 is forbidden"
                    f"{to_hex(sender_details.locksroot)} for sender "
                    f"{to_checksum_address(sender)}."
                )
                raise RaidenUnrecoverableError(msg)

        log_details = {
            "node": to_checksum_address(self.node_address),
            "contract": to_checksum_address(self.address),
            "sender": to_checksum_address(sender),
            "receiver": to_checksum_address(receiver),
            "merkle_tree_locks": merkle_tree_locks,
        }

        with log_transaction(log, "unlock", log_details):
            self._unlock(
                channel_identifier=channel_identifier,
                sender=sender,
                receiver=receiver,
                merkle_tree_locks=merkle_tree_locks,
                given_block_identifier=given_block_identifier,
                log_details=log_details,
            )

    def _unlock(
        self,
        channel_identifier: ChannelID,
        sender: Address,
        receiver: Address,
        merkle_tree_locks: MerkleTreeLeaves,
        given_block_identifier: BlockSpecification,
        log_details: Dict[Any, Any],
    ) -> None:
        checking_block = self.client.get_checking_block()
        leaves_packed = b"".join(lock.encoded for lock in merkle_tree_locks)
        gas_limit = self.proxy.estimate_gas(
            checking_block,
            "unlock",
            channel_identifier=channel_identifier,
            receiver=receiver,
            sender=sender,
            merkle_tree_leaves=leaves_packed,
        )

        if gas_limit:
            gas_limit = safe_gas_limit(gas_limit, UNLOCK_TX_GAS_LIMIT)
            log_details["gas_limit"] = gas_limit

            transaction_hash = self.proxy.transact(
                function_name="unlock",
                startgas=gas_limit,
                channel_identifier=channel_identifier,
                receiver=receiver,
                sender=sender,
                merkle_tree_leaves=leaves_packed,
            )

            self.client.poll(transaction_hash)
            receipt_or_none = check_transaction_threw(self.client, transaction_hash)

            if receipt_or_none:
                # Because the gas estimation succeeded it is known that:
                # - The channel was settled.
                # - The channel had pending locks on-chain for that participant.
                # - The account had enough balance to pay for the gas (however
                #   there is a race condition for multiple transactions #3890)

                if receipt_or_none["cumulativeGasUsed"] == gas_limit:
                    msg = (
                        f"update transfer failed and all gas was used "
                        f"({gas_limit}). Estimate gas may have underestimated "
                        f"update transfer, or succeeded even though an assert is "
                        f"triggered, or the smart contract code has an "
                        f"conditional assert."
                    )
                    raise RaidenUnrecoverableError(msg)

                # Query the current state to check for transaction races
                sender_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=sender,
                    partner=receiver,
                    block_identifier=given_block_identifier,
                )

                is_unlock_done = sender_details.locksroot == EMPTY_MERKLE_ROOT
                if is_unlock_done:
                    raise RaidenRecoverableError("The merkle tree is already unlocked")

                raise RaidenUnrecoverableError("Unlocked failed for an unknown reason")
        else:
            # The transaction would have failed if sent, figure out why.

            # The latest block can not be used reliably because of reorgs,
            # therefore every call using this block has to handle pruned data.
            failed_at = self.proxy.jsonrpc_client.get_block("latest")
            failed_at_blockhash = encode_hex(failed_at["hash"])
            failed_at_blocknumber = failed_at["number"]

            self.proxy.jsonrpc_client.check_for_insufficient_eth(
                transaction_name="unlock",
                transaction_executed=False,
                required_gas=UNLOCK_TX_GAS_LIMIT,
                block_identifier=failed_at_blocknumber,
            )
            detail = self._detail_channel(
                participant1=sender,
                participant2=receiver,
                block_identifier=given_block_identifier,
                channel_identifier=channel_identifier,
            )
            sender_details = self._detail_participant(
                channel_identifier=channel_identifier,
                detail_for=sender,
                partner=receiver,
                block_identifier=failed_at_blockhash,
            )

            if detail.state < ChannelState.SETTLED:
                msg = (
                    f"cannot call unlock on a channel that has not been settled yet. "
                    f"current_state={detail.state}"
                )
                raise RaidenUnrecoverableError(msg)

            is_unlock_done = sender_details.locksroot == EMPTY_MERKLE_ROOT
            if is_unlock_done:
                raise RaidenRecoverableError("The merkle tree is already unlocked ")

            raise RaidenUnrecoverableError("unlock failed for an unknown reason")

    def _settle_preconditions(
        self, channel_identifier: ChannelID, partner: Address, block_identifier: BlockSpecification
    ):
        if not self.client.can_query_state_for_block(block_identifier):
            raise NoStateForBlockIdentifier()

        self._check_for_outdated_channel(
            participant1=self.node_address,
            participant2=partner,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )

    def settle(
        self,
        channel_identifier: ChannelID,
        transferred_amount: TokenAmount,
        locked_amount: TokenAmount,
        locksroot: Locksroot,
        partner: Address,
        partner_transferred_amount: TokenAmount,
        partner_locked_amount: TokenAmount,
        partner_locksroot: Locksroot,
        given_block_identifier: BlockSpecification,
    ):
        checking_block = self.client.get_checking_block()
        our_maximum = transferred_amount + locked_amount
        partner_maximum = partner_transferred_amount + partner_locked_amount

        # The second participant transferred + locked amount must be higher
        our_bp_is_larger = our_maximum > partner_maximum
        if our_bp_is_larger:
            kwargs = {
                "participant1": partner,
                "participant1_transferred_amount": partner_transferred_amount,
                "participant1_locked_amount": partner_locked_amount,
                "participant1_locksroot": partner_locksroot,
                "participant2": self.node_address,
                "participant2_transferred_amount": transferred_amount,
                "participant2_locked_amount": locked_amount,
                "participant2_locksroot": locksroot,
            }
        else:
            kwargs = {
                "participant1": self.node_address,
                "participant1_transferred_amount": transferred_amount,
                "participant1_locked_amount": locked_amount,
                "participant1_locksroot": locksroot,
                "participant2": partner,
                "participant2_transferred_amount": partner_transferred_amount,
                "participant2_locked_amount": partner_locked_amount,
                "participant2_locksroot": partner_locksroot,
            }

        try:
            self._settle_preconditions(
                channel_identifier=channel_identifier,
                partner=partner,
                block_identifier=given_block_identifier,
            )
        except NoStateForBlockIdentifier:
            # If preconditions end up being on pruned state skip them. Estimate
            # gas will stop us from sending a transaction that will fail
            pass

        log_details = {
            "channel_identifier": channel_identifier,
            "contract": to_checksum_address(self.address),
            "node": to_checksum_address(self.node_address),
            "participant1": kwargs["participant1"],
            "participant1_transferred_amount": kwargs["participant1_transferred_amount"],
            "participant1_locked_amount": kwargs["participant1_locked_amount"],
            "participant1_locksroot": encode_hex(kwargs["participant1_locksroot"]),
            "participant2": kwargs["participant2"],
            "participant2_transferred_amount": kwargs["participant2_transferred_amount"],
            "participant2_locked_amount": kwargs["participant2_locked_amount"],
            "participant2_locksroot": encode_hex(kwargs["participant2_locksroot"]),
        }
        with log_transaction(log, "settle", log_details):
            with self.channel_operations_lock[partner]:
                error_prefix = "Call to settle will fail"
                gas_limit = self.proxy.estimate_gas(
                    checking_block,
                    "settleChannel",
                    channel_identifier=channel_identifier,
                    **kwargs,
                )

                if gas_limit:
                    error_prefix = "settle call failed"
                    gas_limit = safe_gas_limit(gas_limit, GAS_REQUIRED_FOR_SETTLE_CHANNEL)
                    log_details["gas_limit"] = gas_limit

                    transaction_hash = self.proxy.transact(
                        "settleChannel", gas_limit, channel_identifier=channel_identifier, **kwargs
                    )
                    self.client.poll(transaction_hash)
                    receipt_or_none = check_transaction_threw(self.client, transaction_hash)

            transaction_executed = gas_limit is not None
            if not transaction_executed or receipt_or_none:
                if transaction_executed:
                    block = receipt_or_none["blockNumber"]
                else:
                    block = checking_block

                self.proxy.jsonrpc_client.check_for_insufficient_eth(
                    transaction_name="settleChannel",
                    transaction_executed=transaction_executed,
                    required_gas=GAS_REQUIRED_FOR_SETTLE_CHANNEL,
                    block_identifier=block,
                )
                msg = self._check_channel_state_after_settle(
                    participant1=self.node_address,
                    participant2=partner,
                    block_identifier=block,
                    channel_identifier=channel_identifier,
                )
                raise RaidenUnrecoverableError(f"{error_prefix}. {msg}")

    def events_filter(
        self,
        topics: List[str] = None,
        from_block: BlockSpecification = None,
        to_block: BlockSpecification = None,
    ) -> StatelessFilter:
        """ Install a new filter for an array of topics emitted by the contract.

        Args:
            topics: A list of event ids to filter for. Can also be None,
                    in which case all events are queried.
            from_block: The block number at which to start looking for events.
            to_block: The block number at which to stop looking for events.
        Return:
            Filter: The filter instance.
        """
        return self.client.new_filter(
            self.address, topics=topics, from_block=from_block, to_block=to_block
        )

    def all_events_filter(
        self,
        from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
        to_block: BlockSpecification = "latest",
    ) -> StatelessFilter:
        """ Install a new filter for all the events emitted by the current token network contract

        Args:
            from_block: Create filter starting from this block number (default: 0).
            to_block: Create filter stopping at this block number (default: 'latest').

        Return:
            The filter instance.
        """
        return self.events_filter(None, from_block, to_block)

    def _check_for_outdated_channel(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockSpecification,
        channel_identifier: ChannelID,
    ) -> None:
        """
        Checks whether an operation is being executed on a channel
        between two participants using an old channel identifier
        """
        try:
            onchain_channel_details = self._detail_channel(
                participant1=participant1,
                participant2=participant2,
                block_identifier=block_identifier,
            )
        except RaidenRecoverableError:
            return

        onchain_channel_identifier = onchain_channel_details.channel_identifier

        if onchain_channel_identifier != channel_identifier:
            raise ChannelOutdatedError(
                "Current channel identifier is outdated. "
                f"current={channel_identifier}, "
                f"new={onchain_channel_identifier}"
            )

    def _get_channel_state(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockSpecification,
        channel_identifier: ChannelID = None,
    ) -> ChannelState:
        channel_data = self._detail_channel(
            participant1=participant1,
            participant2=participant2,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )

        typecheck(channel_data.state, T_ChannelState)

        return channel_data.state

    def _check_channel_state_before_settle(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockSpecification,
        channel_identifier: ChannelID,
    ) -> ChannelData:

        channel_data = self._detail_channel(
            participant1=participant1,
            participant2=participant2,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )
        if channel_data.state == ChannelState.SETTLED:
            raise RaidenRecoverableError("Channel is already settled")
        elif channel_data.state == ChannelState.REMOVED:
            raise RaidenRecoverableError("Channel is already unlocked. It cannot be settled")
        elif channel_data.state == ChannelState.OPENED:
            raise RaidenUnrecoverableError("Channel is still open. It cannot be settled")
        elif channel_data.state == ChannelState.CLOSED:
            if self.client.block_number() < channel_data.settle_block_number:
                raise RaidenUnrecoverableError(
                    "Channel cannot be settled before settlement window is over"
                )

        return channel_data

    def _check_channel_state_after_settle(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockSpecification,
        channel_identifier: ChannelID,
    ) -> str:
        msg = ""
        channel_data = self._check_channel_state_before_settle(
            participant1=participant1,
            participant2=participant2,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )
        if channel_data.state == ChannelState.CLOSED:
            msg = "Settling this channel failed although the channel's current state " "is closed."
        return msg
