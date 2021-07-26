from collections import defaultdict
from dataclasses import dataclass

import structlog
from eth_utils import encode_hex, is_binary_address, to_canonical_address, to_hex
from gevent.lock import RLock
from web3.exceptions import BadFunctionCallOutput

from raiden.constants import (
    BLOCK_ID_LATEST,
    EMPTY_BALANCE_HASH,
    EMPTY_SIGNATURE,
    LOCKSROOT_OF_NO_LOCKS,
    NULL_ADDRESS_BYTES,
    UINT256_MAX,
    UNLOCK_TX_GAS_LIMIT,
)
from raiden.exceptions import (
    BrokenPreconditionError,
    DepositOverLimit,
    DuplicatedChannelError,
    InvalidChannelID,
    InvalidSettleTimeout,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
    SamePeerAddress,
    WithdrawMismatch,
)
from raiden.network.proxies.metadata import SmartContractMetadata
from raiden.network.proxies.utils import raise_on_call_returned_empty
from raiden.network.rpc.client import (
    JSONRPCClient,
    check_address_has_code_handle_pruned_block,
    check_transaction_failure,
    was_transaction_successfully_mined,
)
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import PendingLocksState
from raiden.transfer.utils import hash_balance_data
from raiden.utils.formatting import format_block_id, to_checksum_address
from raiden.utils.packing import pack_balance_proof, pack_signed_balance_proof, pack_withdraw
from raiden.utils.signer import recover
from raiden.utils.smart_contracts import safe_gas_limit
from raiden.utils.typing import (
    TYPE_CHECKING,
    AdditionalHash,
    Address,
    Any,
    BalanceHash,
    BlockExpiration,
    BlockHash,
    BlockIdentifier,
    BlockNumber,
    ChainID,
    ChannelID,
    Dict,
    LockedAmount,
    Locksroot,
    NamedTuple,
    Nonce,
    Optional,
    Signature,
    T_ChannelID,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    TransactionHash,
    WithdrawAmount,
    typecheck,
)
from raiden_contracts.constants import (
    CONTRACT_TOKEN_NETWORK,
    ChannelInfoIndex,
    ChannelState,
    MessageTypeId,
    ParticipantInfoIndex,
)
from raiden_contracts.contract_manager import ContractManager

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.network.proxies.proxy_manager import ProxyManager


log = structlog.get_logger(__name__)


def raise_if_invalid_address_pair(address1: Address, address2: Address) -> None:
    msg = "The null address is not allowed as a channel participant."
    assert NULL_ADDRESS_BYTES not in (address1, address2), msg
    msg = "Addresses must be in binary"
    assert is_binary_address(address1) and is_binary_address(address2), msg

    if address1 == address2:
        raise SamePeerAddress("Using the same address for both participants is forbiden.")


class WithdrawInput(NamedTuple):
    initiator: Address
    total_withdraw: WithdrawAmount
    expiration_block: BlockExpiration
    initiator_signature: Signature
    partner_signature: Signature


class ChannelData(NamedTuple):
    channel_identifier: ChannelID
    settle_block_number: BlockNumber
    state: ChannelState


class ParticipantDetails(NamedTuple):
    address: Address
    deposit: TokenAmount
    withdrawn: WithdrawAmount
    is_closer: bool
    balance_hash: BalanceHash
    nonce: Nonce
    locksroot: Locksroot
    locked_amount: LockedAmount


class ParticipantsDetails(NamedTuple):
    our_details: ParticipantDetails
    partner_details: ParticipantDetails


class ChannelDetails(NamedTuple):
    chain_id: ChainID
    token_address: TokenAddress
    channel_data: ChannelData
    participants_data: ParticipantsDetails


class NewNettingChannelDetails(NamedTuple):
    channel_identifier: ChannelID
    block_hash: BlockHash
    block_number: BlockNumber
    transaction_hash: TransactionHash


@dataclass
class TokenNetworkMetadata(SmartContractMetadata):
    token_network_registry_address: Optional[TokenNetworkRegistryAddress]


class TokenNetwork:
    def __init__(
        self,
        jsonrpc_client: JSONRPCClient,
        contract_manager: ContractManager,
        proxy_manager: "ProxyManager",
        metadata: TokenNetworkMetadata,
        block_identifier: BlockIdentifier,
    ) -> None:
        if not is_binary_address(metadata.address):
            raise ValueError("Expected binary address format for token nework")

        check_address_has_code_handle_pruned_block(
            client=jsonrpc_client,
            address=Address(metadata.address),
            contract_name=CONTRACT_TOKEN_NETWORK,
            given_block_identifier=block_identifier,
        )

        self.contract_manager = contract_manager
        proxy = jsonrpc_client.new_contract_proxy(
            abi=metadata.abi, contract_address=Address(metadata.address)
        )

        # These are constants
        self._chain_id = proxy.functions.chain_id().call()
        self._token_address = TokenAddress(to_canonical_address(proxy.functions.token().call()))

        self.address = TokenNetworkAddress(metadata.address)
        self.proxy = proxy
        self.client = jsonrpc_client
        self.node_address = self.client.address
        self.metadata = metadata

        self.token = proxy_manager.token(
            token_address=self.token_address(), block_identifier=block_identifier
        )

        # Forbids concurrent operations on the same channel. This is important
        # because some operations conflict with each other. E.g. deposit and
        # close, in this case if the node is lucky the close will be performed
        # before the deposit, and the deposit transactions will not be sent.
        #
        # Note: unlock doesn't have to be synchronized, after settlement the
        # channel doesn't exist anymore.
        self.channel_operations_lock: Dict[Address, RLock] = defaultdict(RLock)
        self.opening_channels_count = 0

    def chain_id(self) -> ChainID:
        """Return the token of this manager."""
        return self._chain_id

    def token_address(self) -> TokenAddress:
        """Return the token of this manager."""
        return self._token_address

    def channel_participant_deposit_limit(self, block_identifier: BlockIdentifier) -> TokenAmount:
        """Return the deposit limit of a channel participant."""
        return TokenAmount(
            self.proxy.functions.channel_participant_deposit_limit().call(
                block_identifier=block_identifier
            )
        )

    def token_network_deposit_limit(self, block_identifier: BlockIdentifier) -> TokenAmount:
        """Return the token of this manager."""
        return TokenAmount(
            self.proxy.functions.token_network_deposit_limit().call(
                block_identifier=block_identifier
            )
        )

    def safety_deprecation_switch(self, block_identifier: BlockIdentifier) -> bool:
        return self.proxy.functions.safety_deprecation_switch().call(
            block_identifier=block_identifier
        )

    def new_netting_channel(
        self, partner: Address, settle_timeout: int, given_block_identifier: BlockIdentifier
    ) -> NewNettingChannelDetails:
        """Creates a new channel in the TokenNetwork contract.

        Args:
            partner: The peer to open the channel with.
            settle_timeout: The settle timeout to use for this channel.
            given_block_identifier: The block identifier of the state change that
                                    prompted this proxy action

        Returns:
            The ChannelID of the new netting channel.
        """
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

        # Currently only one channel per address pair is allowed. I.e. if the
        # node sends two transactions to open a channel with the same partner
        # in a row, the second transaction will fail. This lock prevents the
        # second, wasteful transaction from happening.
        with self.channel_operations_lock[partner]:
            # check preconditions
            try:
                existing_channel_identifier = self.get_channel_identifier_or_none(
                    participant1=self.node_address,
                    participant2=partner,
                    block_identifier=given_block_identifier,
                )
                network_total_deposit = self.token.balance_of(
                    address=Address(self.address), block_identifier=given_block_identifier
                )
                limit = self.token_network_deposit_limit(block_identifier=given_block_identifier)
                safety_deprecation_switch = self.safety_deprecation_switch(given_block_identifier)
            except ValueError:
                # If `given_block_identifier` has been pruned the checks cannot be
                # performed.
                pass
            except BadFunctionCallOutput:
                raise_on_call_returned_empty(given_block_identifier)
            else:
                if existing_channel_identifier is not None:
                    raise BrokenPreconditionError(
                        "A channel with the given partner address already exists."
                    )
                if network_total_deposit >= limit:
                    raise BrokenPreconditionError(
                        "Cannot open another channel, token network deposit limit reached."
                    )
                if safety_deprecation_switch:
                    raise BrokenPreconditionError("This token network is deprecated.")

            self.opening_channels_count += 1
            try:
                netting_channel_details = self._new_netting_channel(partner, settle_timeout)
            finally:
                self.opening_channels_count -= 1

            return netting_channel_details

    def _new_netting_channel(
        self, partner: Address, settle_timeout: int
    ) -> NewNettingChannelDetails:
        estimated_transaction = self.client.estimate_gas(
            self.proxy,
            "openChannel",
            extra_log_details={},
            participant1=self.node_address,
            participant2=partner,
            settle_timeout=settle_timeout,
        )

        if estimated_transaction is None:
            failed_at = self.client.get_block(BLOCK_ID_LATEST)
            failed_at_blockhash = encode_hex(failed_at["hash"])
            failed_at_blocknumber = failed_at["number"]

            self.client.check_for_insufficient_eth(
                transaction_name="openChannel",
                transaction_executed=False,
                required_gas=self.metadata.gas_measurements["TokenNetwork.openChannel"],
                block_identifier=failed_at_blocknumber,
            )

            existing_channel_identifier = self.get_channel_identifier_or_none(
                participant1=self.node_address,
                participant2=partner,
                block_identifier=failed_at_blockhash,
            )
            if existing_channel_identifier is not None:
                raise DuplicatedChannelError("Channel with given partner address already exists")

            network_total_deposit = self.token.balance_of(
                address=Address(self.address), block_identifier=failed_at_blockhash
            )
            limit = self.token_network_deposit_limit(block_identifier=failed_at_blockhash)
            if network_total_deposit >= limit:
                raise DepositOverLimit(
                    "Could open another channel, token network deposit limit has been reached."
                )

            if self.safety_deprecation_switch(block_identifier=failed_at_blockhash):
                raise RaidenRecoverableError("This token network is deprecated.")

            raise RaidenRecoverableError(
                f"Creating a new channel will fail - Gas estimation failed for "
                f"unknown reason. Reference block {failed_at_blockhash} "
                f"{failed_at_blocknumber}."
            )
        else:
            estimated_transaction.estimated_gas = safe_gas_limit(
                estimated_transaction.estimated_gas,
                self.metadata.gas_measurements["TokenNetwork.openChannel"],
            )
            transaction_sent = self.client.transact(estimated_transaction)
            transaction_mined = self.client.poll_transaction(transaction_sent)
            receipt = transaction_mined.receipt

            if not was_transaction_successfully_mined(transaction_mined):
                failed_at_blockhash = encode_hex(receipt["blockHash"])
                existing_channel_identifier = self.get_channel_identifier_or_none(
                    participant1=self.node_address,
                    participant2=partner,
                    block_identifier=failed_at_blockhash,
                )
                if existing_channel_identifier is not None:
                    raise DuplicatedChannelError(
                        "Channel with given partner address already exists"
                    )

                network_total_deposit = self.token.balance_of(
                    address=Address(self.address), block_identifier=failed_at_blockhash
                )
                limit = self.token_network_deposit_limit(block_identifier=failed_at_blockhash)
                if network_total_deposit >= limit:
                    raise DepositOverLimit(
                        "Could open another channel, token network deposit limit has been reached."
                    )

                if self.safety_deprecation_switch(block_identifier=failed_at_blockhash):
                    raise RaidenRecoverableError("This token network is deprecated.")

                raise RaidenRecoverableError("Creating new channel failed.")

        channel_identifier: ChannelID = self._detail_channel(
            participant1=self.node_address,
            participant2=partner,
            block_identifier=encode_hex(receipt["blockHash"]),
        ).channel_identifier

        return NewNettingChannelDetails(
            channel_identifier=channel_identifier,
            block_hash=BlockHash(receipt["blockHash"]),
            block_number=BlockNumber(receipt["blockNumber"]),
            transaction_hash=TransactionHash(transaction_mined.transaction_hash),
        )

    def get_channel_identifier(
        self, participant1: Address, participant2: Address, block_identifier: BlockIdentifier
    ) -> ChannelID:
        """Return the channel identifier for the opened channel among
        `(participant1, participant2)`.

        Raises:
            RaidenRecoverableError: If there is not open channel among
                `(participant1, participant2)`. Note this is the case even if
                there is a channel in a settled state.
            BadFunctionCallOutput: If the `block_identifier` points to a block
                prior to the deployment of the TokenNetwork.
            SamePeerAddress: If an both addresses are equal.
        """
        raise_if_invalid_address_pair(participant1, participant2)

        channel_identifier = self.proxy.functions.getChannelIdentifier(
            participant=participant1, partner=participant2
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

    def get_channel_identifier_or_none(
        self, participant1: Address, participant2: Address, block_identifier: BlockIdentifier
    ) -> Optional[ChannelID]:
        """Returns the channel identifier if an open channel exists, else None."""
        try:
            return self.get_channel_identifier(
                participant1=participant1,
                participant2=participant2,
                block_identifier=block_identifier,
            )
        except RaidenRecoverableError:
            return None

    def _detail_participant(
        self,
        channel_identifier: ChannelID,
        detail_for: Address,
        partner: Address,
        block_identifier: BlockIdentifier,
    ) -> ParticipantDetails:
        """Returns a dictionary with the channel participant information."""
        raise_if_invalid_address_pair(detail_for, partner)

        data = self.proxy.functions.getChannelParticipantInfo(
            channel_identifier=channel_identifier, participant=detail_for, partner=partner
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
        block_identifier: BlockIdentifier,
        channel_identifier: ChannelID = None,
    ) -> ChannelData:
        """Returns a ChannelData instance with the channel specific information.

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

        channel_data = self.proxy.functions.getChannelInfo(
            channel_identifier=channel_identifier,
            participant1=participant1,
            participant2=participant2,
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
        block_identifier: BlockIdentifier,
        channel_identifier: ChannelID = None,
    ) -> ParticipantsDetails:
        """Returns a ParticipantsDetails instance with the participants'
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
        block_identifier: BlockIdentifier,
        channel_identifier: ChannelID = None,
    ) -> ChannelDetails:
        """Returns a ChannelDetails instance with all the details of the
            channel and the channel participants.

        Note:
            For now one of the participants has to be the node_address
        """
        if self.node_address not in (participant1, participant2):
            raise ValueError("One participant must be the node address")

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
        chain_id = self.chain_id()

        return ChannelDetails(
            chain_id=chain_id,
            token_address=self.token_address(),
            channel_data=channel_data,
            participants_data=participants_data,
        )

    def settlement_timeout_min(self) -> int:
        """Returns the minimal settlement timeout for the token network."""
        return self.proxy.functions.settlement_timeout_min().call()

    def settlement_timeout_max(self) -> int:
        """Returns the maximal settlement timeout for the token network."""
        return self.proxy.functions.settlement_timeout_max().call()

    def channel_is_opened(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockIdentifier,
        channel_identifier: ChannelID,
    ) -> bool:
        """Returns true if the channel is in an open state, false otherwise."""
        try:
            channel_data = self._detail_channel(
                participant1=participant1,
                participant2=participant2,
                block_identifier=block_identifier,
                channel_identifier=channel_identifier,
            )
        except RaidenRecoverableError:
            return False
        return channel_data.state == ChannelState.OPENED

    def channel_is_closed(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockIdentifier,
        channel_identifier: ChannelID,
    ) -> bool:
        """Returns true if the channel is in a closed state, false otherwise."""
        try:
            channel_data = self._detail_channel(
                participant1=participant1,
                participant2=participant2,
                block_identifier=block_identifier,
                channel_identifier=channel_identifier,
            )
        except RaidenRecoverableError:
            return False
        return channel_data.state == ChannelState.CLOSED

    def channel_is_settled(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockIdentifier,
        channel_identifier: ChannelID,
    ) -> bool:
        """Returns true if the channel is in a settled state, false otherwise."""
        try:
            channel_data = self._detail_channel(
                participant1=participant1,
                participant2=participant2,
                block_identifier=block_identifier,
                channel_identifier=channel_identifier,
            )
        except RaidenRecoverableError:
            return False
        return channel_data.state >= ChannelState.SETTLED

    def can_transfer(
        self,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockIdentifier,
        channel_identifier: ChannelID,
    ) -> bool:
        """Returns True if the channel is opened and the node has deposit in
        it.

        Note: Having a deposit does not imply having a balance for off-chain
        transfers."""
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

    def approve_and_set_total_deposit(
        self,
        given_block_identifier: BlockIdentifier,
        channel_identifier: ChannelID,
        total_deposit: TokenAmount,
        partner: Address,
    ) -> TransactionHash:
        """Set channel's total deposit.

        `total_deposit` has to be monotonically increasing, this is enforced by
        the `TokenNetwork` smart contract. This is done for the same reason why
        the balance proofs have a monotonically increasing transferred amount,
        it simplifies the analysis of bad behavior and the handling code of
        out-dated balance proofs.

        Races to `approve_and_set_total_deposit` are handled by the smart contract, where
        largest total deposit wins. The end balance of the funding accounts is
        undefined. E.g.

        - Acc1 calls approve_and_set_total_deposit with 10 tokens
        - Acc2 calls approve_and_set_total_deposit with 13 tokens

        - If Acc2's transaction is mined first, then Acc1 token supply is left intact.
        - If Acc1's transaction is mined first, then Acc2 will only move 3 tokens.

        Races for the same account don't have any unexpected side-effect.

        Raises:
            DepositMismatch: If the new request total deposit is lower than the
                existing total deposit on-chain for the `given_block_identifier`.
            RaidenRecoverableError: If the channel was closed meanwhile the
                deposit was in transit.
            RaidenUnrecoverableError: If the transaction was successful and the
                deposit_amount is not as large as the requested value.
            RuntimeError: If the token address is empty.
            ValueError: If an argument is of the invalid type.
        """
        typecheck(total_deposit, int)

        if total_deposit <= 0 and total_deposit > UINT256_MAX:
            msg = f"Total deposit {total_deposit} is not in range [1, {UINT256_MAX}]"
            raise BrokenPreconditionError(msg)

        # `channel_operations_lock` is used to serialize conflicting channel
        # operations. E.g. this deposit and a close.
        #
        # A channel deposit with the ERC20 standard has two requirements. First
        # the user's account must have balance, second the token network must
        # have an allowance at least as high as the value of the deposit; To
        # prevent another thread from concurrently changing these values and
        # invalidating the deposit, the token lock is acquired. This does not
        # prevent conflicting operations from being requested, but it does
        # enforces an order to make easier to reason about errors.
        #
        # The account balance is checked implicitly by the gas estimation. If
        # there is not enough balance in the account either a require or assert
        # is hit, which makes the gas estimation fail. However, this only works
        # for transactions that have been mined, so there can not be two
        # transactions in-flight that move tokens from the same address.
        #
        # The token network allowace is a bit trickier, because consecutive
        # calls to approve are not idempotent. If two channels are being open
        # at the same time, the transactions must not be ordered as `approve +
        # approve + deposit + deposit`, since the second approve will overwrite
        # the first and at least one of the deposits will fail. Because of
        # this, the allowance can not change until the deposit is done.
        with self.channel_operations_lock[partner]:
            try:
                queried_channel_identifier = self.get_channel_identifier_or_none(
                    participant1=self.node_address,
                    participant2=partner,
                    block_identifier=given_block_identifier,
                )
                channel_onchain_detail = self._detail_channel(
                    participant1=self.node_address,
                    participant2=partner,
                    block_identifier=given_block_identifier,
                    channel_identifier=channel_identifier,
                )
                our_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=self.node_address,
                    partner=partner,
                    block_identifier=given_block_identifier,
                )
                partner_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=partner,
                    partner=self.node_address,
                    block_identifier=given_block_identifier,
                )
                current_balance = self.token.balance_of(
                    address=self.node_address, block_identifier=given_block_identifier
                )
                safety_deprecation_switch = self.safety_deprecation_switch(
                    block_identifier=given_block_identifier
                )
                token_network_deposit_limit = self.token_network_deposit_limit(
                    block_identifier=given_block_identifier
                )
                channel_participant_deposit_limit = self.channel_participant_deposit_limit(
                    block_identifier=given_block_identifier
                )
                network_total_deposit = self.token.balance_of(
                    address=Address(self.address), block_identifier=given_block_identifier
                )
            except ValueError:
                # If `given_block_identifier` has been pruned the checks cannot be
                # performed.
                our_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=self.node_address,
                    partner=partner,
                    block_identifier=BLOCK_ID_LATEST,
                )
            except BadFunctionCallOutput:
                raise_on_call_returned_empty(given_block_identifier)
            else:
                if queried_channel_identifier != channel_identifier:
                    msg = (
                        f"There is a channel open between "
                        f"{to_checksum_address(self.node_address)} and "
                        f"{to_checksum_address(partner)}. However the channel id "
                        f"on-chain {queried_channel_identifier} and the provided "
                        f"id {channel_identifier} do not match."
                    )
                    raise BrokenPreconditionError(msg)

                if safety_deprecation_switch:
                    msg = "This token_network has been deprecated."
                    raise BrokenPreconditionError(msg)

                if channel_onchain_detail.state != ChannelState.OPENED:
                    msg = (
                        f"The channel was not opened at the provided block "
                        f"({format_block_id(given_block_identifier)}). This call "
                        f"should never have been attempted."
                    )
                    raise BrokenPreconditionError(msg)

                amount_to_deposit = total_deposit - our_details.deposit

                if total_deposit <= our_details.deposit:
                    msg = (
                        f"Current total deposit ({our_details.deposit}) is already larger "
                        f"than the requested total deposit amount ({total_deposit})"
                    )
                    raise BrokenPreconditionError(msg)

                total_channel_deposit = total_deposit + partner_details.deposit
                if total_channel_deposit > UINT256_MAX:
                    raise BrokenPreconditionError("Deposit overflow")

                if total_deposit > channel_participant_deposit_limit:
                    msg = (
                        f"Deposit of {total_deposit} is larger than the "
                        f"channel participant deposit limit"
                    )
                    raise BrokenPreconditionError(msg)

                if network_total_deposit + amount_to_deposit > token_network_deposit_limit:
                    msg = (
                        f"Deposit of {amount_to_deposit} will have "
                        f"exceeded the token network deposit limit."
                    )
                    raise BrokenPreconditionError(msg)

                if current_balance < amount_to_deposit:
                    msg = (
                        f"new_total_deposit - previous_total_deposit =  {amount_to_deposit} can "
                        f"not be larger than the available balance {current_balance}, "
                        f"for token at address {to_checksum_address(self.token.address)}"
                    )
                    raise BrokenPreconditionError(msg)

            log_details = {
                "previous_total_deposit": our_details.deposit,
                "given_block_identifier": format_block_id(given_block_identifier),
            }

            return self._approve_and_set_total_deposit(
                channel_identifier=channel_identifier,
                total_deposit=total_deposit,
                previous_total_deposit=our_details.deposit,
                partner=partner,
                log_details=log_details,
            )

    def _approve_and_set_total_deposit(
        self,
        channel_identifier: ChannelID,
        total_deposit: TokenAmount,
        partner: Address,
        previous_total_deposit: TokenAmount,
        log_details: Dict[Any, Any],
    ) -> TransactionHash:
        amount_to_deposit = TokenAmount(total_deposit - previous_total_deposit)

        # If there are channels being set up concurrently either the
        # allowance must be accumulated *or* the calls to `approve` and
        # `setTotalDeposit` must be serialized. This is necessary otherwise
        # the deposit will fail.
        #
        # Calls to `approve` and `setTotalDeposit` are serialized with the
        # `token_lock` to avoid transaction failure, because with two
        # concurrent deposits, we may have the transactions executed in the
        # following order
        #
        # - approve
        # - approve
        # - setTotalDeposit
        # - setTotalDeposit
        #
        # in which case the second `approve` will overwrite the first,
        # and the first `setTotalDeposit` will consume the allowance,
        # making the second deposit fail.
        estimated_transaction = None
        with self.token.token_lock:
            # HACK: The hack below is necessary to make sure the gas
            # estimation of an approve works concurrently with the mining of a
            # deposit. If the *exact* amount is used, the storage of the smart
            # contract will be set to `0` once the `deposit` is mined, this
            # means the gas estimation of an approve done before the deposit
            # was mined will be off by the 20_000 required by the `SSTORE` to
            # change the value back from `0`.
            allowance = TokenAmount(amount_to_deposit + 1)
            self.token.approve(allowed_address=Address(self.address), allowance=allowance)

            estimated_transaction = self.client.estimate_gas(
                self.proxy,
                "setTotalDeposit",
                extra_log_details=log_details,
                channel_identifier=channel_identifier,
                participant=self.node_address,
                total_deposit=total_deposit,
                partner=partner,
            )

        if estimated_transaction is not None:
            estimated_transaction.estimated_gas = safe_gas_limit(
                estimated_transaction.estimated_gas,
                self.metadata.gas_measurements["TokenNetwork.setTotalDeposit"],
            )
            transaction_sent = self.client.transact(estimated_transaction)
            transaction_mined = self.client.poll_transaction(transaction_sent)

            if not was_transaction_successfully_mined(transaction_mined):
                receipt = transaction_mined.receipt
                # Because the gas estimation succeeded it is known that:
                # - The channel id was correct, i.e. this node and partner are
                #   participants of the chanenl with id `channel_identifier`.
                # - The channel was open.
                # - The account had enough tokens to deposit
                # - The account had enough balance to pay for the gas (however
                #   there is a race condition for multiple transactions #3890)
                failed_at_blockhash = encode_hex(receipt["blockHash"])
                failed_at_blocknumber = BlockNumber(receipt["blockNumber"])

                check_transaction_failure(transaction_mined, self.client)

                safety_deprecation_switch = self.safety_deprecation_switch(
                    block_identifier=failed_at_blockhash
                )
                if safety_deprecation_switch:
                    msg = "This token_network has been deprecated."
                    raise RaidenRecoverableError(msg)

                # Query the channel state when the transaction was mined
                # to check for transaction races
                our_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=self.node_address,
                    partner=partner,
                    block_identifier=failed_at_blockhash,
                )
                partner_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=self.node_address,
                    partner=partner,
                    block_identifier=failed_at_blockhash,
                )
                channel_data = self._detail_channel(
                    participant1=self.node_address,
                    participant2=partner,
                    block_identifier=failed_at_blockhash,
                    channel_identifier=channel_identifier,
                )

                if channel_data.state == ChannelState.CLOSED:
                    msg = "Deposit failed because the channel was closed meanwhile"
                    raise RaidenRecoverableError(msg)

                if channel_data.state == ChannelState.SETTLED:
                    msg = "Deposit failed because the channel was settled meanwhile"
                    raise RaidenRecoverableError(msg)

                if channel_data.state == ChannelState.REMOVED:
                    msg = "Deposit failed because the channel was settled and unlocked meanwhile"
                    raise RaidenRecoverableError(msg)

                deposit_amount = total_deposit - our_details.deposit

                # If an overflow is possible then we are interacting with a bad token.
                # This must not crash the client, because it is not a Raiden bug,
                # and otherwise this could be an attack vector.
                total_channel_deposit = total_deposit + partner_details.deposit
                if total_channel_deposit > UINT256_MAX:
                    raise RaidenRecoverableError("Deposit overflow")

                total_deposit_done = our_details.deposit >= total_deposit
                if total_deposit_done:
                    raise RaidenRecoverableError("Requested total deposit was already performed")

                token_network_deposit_limit = self.token_network_deposit_limit(
                    block_identifier=receipt["blockHash"]
                )

                network_total_deposit = self.token.balance_of(
                    address=Address(self.address), block_identifier=receipt["blockHash"]
                )

                if network_total_deposit + deposit_amount > token_network_deposit_limit:
                    msg = (
                        f"Deposit of {deposit_amount} would have "
                        f"exceeded the token network deposit limit."
                    )
                    raise RaidenRecoverableError(msg)

                channel_participant_deposit_limit = self.channel_participant_deposit_limit(
                    block_identifier=receipt["blockHash"]
                )
                if total_deposit > channel_participant_deposit_limit:
                    msg = (
                        f"Deposit of {total_deposit} is larger than the "
                        f"channel participant deposit limit"
                    )
                    raise RaidenRecoverableError(msg)

                has_sufficient_balance = (
                    self.token.balance_of(self.node_address, failed_at_blocknumber)
                    < amount_to_deposit
                )
                if not has_sufficient_balance:
                    raise RaidenRecoverableError(
                        "The account does not have enough balance to complete the deposit"
                    )

                allowance = self.token.allowance(
                    owner=self.node_address,
                    spender=Address(self.address),
                    block_identifier=failed_at_blockhash,
                )
                if allowance < amount_to_deposit:
                    msg = (
                        f"The allowance of the {amount_to_deposit} deposit changed. "
                        f"Check concurrent deposits "
                        f"for the same token network but different proxies."
                    )
                    raise RaidenRecoverableError(msg)

                latest_deposit = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=self.node_address,
                    partner=partner,
                    block_identifier=failed_at_blockhash,
                ).deposit
                if latest_deposit < total_deposit:
                    raise RaidenRecoverableError("The tokens were not transferred")

                # Here, we don't know what caused the failure. But because we are
                # dealing with an external token contract, it is assumed that it is
                # malicious and therefore we raise a Recoverable error here.
                raise RaidenRecoverableError("Unlocked failed for an unknown reason")
            else:
                return transaction_mined.transaction_hash
        else:
            # The latest block can not be used reliably because of reorgs,
            # therefore every call using this block has to handle pruned data.
            failed_at = self.client.get_block(BLOCK_ID_LATEST)
            failed_at_blockhash = encode_hex(failed_at["hash"])
            failed_at_blocknumber = failed_at["number"]

            self.client.check_for_insufficient_eth(
                transaction_name="setTotalDeposit",
                transaction_executed=False,
                required_gas=self.metadata.gas_measurements["TokenNetwork.setTotalDeposit"],
                block_identifier=failed_at_blocknumber,
            )

            safety_deprecation_switch = self.safety_deprecation_switch(
                block_identifier=failed_at_blockhash
            )
            if safety_deprecation_switch:
                msg = "This token_network has been deprecated."
                raise RaidenRecoverableError(msg)

            allowance = self.token.allowance(
                owner=self.node_address,
                spender=Address(self.address),
                block_identifier=failed_at_blockhash,
            )
            has_sufficient_balance = (
                self.token.balance_of(self.node_address, failed_at_blocknumber) < amount_to_deposit
            )
            if allowance < amount_to_deposit:
                msg = (
                    "The allowance is insufficient. Check concurrent deposits "
                    "for the same token network but different proxies."
                )
                raise RaidenRecoverableError(msg)

            if has_sufficient_balance:
                msg = "The address doesnt have enough tokens"
                raise RaidenRecoverableError(msg)

            queried_channel_identifier = self.get_channel_identifier_or_none(
                participant1=self.node_address,
                participant2=partner,
                block_identifier=failed_at_blockhash,
            )
            our_details = self._detail_participant(
                channel_identifier=channel_identifier,
                detail_for=self.node_address,
                partner=partner,
                block_identifier=failed_at_blockhash,
            )
            partner_details = self._detail_participant(
                channel_identifier=channel_identifier,
                detail_for=self.node_address,
                partner=partner,
                block_identifier=failed_at_blockhash,
            )
            channel_data = self._detail_channel(
                participant1=self.node_address,
                participant2=partner,
                block_identifier=failed_at_blockhash,
                channel_identifier=channel_identifier,
            )
            token_network_deposit_limit = self.token_network_deposit_limit(
                block_identifier=failed_at_blockhash
            )
            channel_participant_deposit_limit = self.channel_participant_deposit_limit(
                block_identifier=failed_at_blockhash
            )

            total_channel_deposit = total_deposit + partner_details.deposit

            network_total_deposit = self.token.balance_of(
                Address(self.address), failed_at_blocknumber
            )

            # This check can only be done if the channel is in the open/closed
            # states because from the settled state and after the id is removed
            # from the smart contract.
            is_invalid_channel_id = (
                channel_data.state in (ChannelState.OPENED, ChannelState.CLOSED)
                and queried_channel_identifier != channel_identifier
            )
            if is_invalid_channel_id:
                msg = (
                    f"There is an open channel with the id {channel_identifier}. "
                    f"However addresses {to_checksum_address(self.node_address)} "
                    f"and {to_checksum_address(partner)} are not participants of "
                    f"that channel. The correct id is {queried_channel_identifier}."
                )
                raise RaidenUnrecoverableError(msg)  # This error is considered a bug

            if channel_data.state == ChannelState.CLOSED:
                msg = "Deposit was prohibited because the channel is closed"
                raise RaidenRecoverableError(msg)

            if channel_data.state == ChannelState.SETTLED:
                msg = "Deposit was prohibited because the channel is settled"
                raise RaidenRecoverableError(msg)

            if channel_data.state == ChannelState.REMOVED:
                msg = "Deposit was prohibited because the channel is settled and unlocked"
                raise RaidenRecoverableError(msg)

            if our_details.deposit >= total_deposit:
                msg = "Attempted deposit has already been done"
                raise RaidenRecoverableError(msg)

            # Check if deposit is being made on a nonexistent channel
            if channel_data.state == ChannelState.NONEXISTENT:
                msg = (
                    f"Channel between participant {to_checksum_address(self.node_address)} "
                    f"and {to_checksum_address(partner)} does not exist"
                )
                raise RaidenUnrecoverableError(msg)

            if total_channel_deposit >= UINT256_MAX:
                raise RaidenRecoverableError("Deposit overflow")

            if total_deposit > channel_participant_deposit_limit:
                msg = (
                    f"Deposit of {total_deposit} exceeded the "
                    f"channel participant deposit limit"
                )
                raise RaidenRecoverableError(msg)

            if network_total_deposit + amount_to_deposit > token_network_deposit_limit:
                msg = f"Deposit of {amount_to_deposit} exceeded the token network deposit limit."
                raise RaidenRecoverableError(msg)

            raise RaidenRecoverableError(
                f"Deposit gas estimatation failed for unknown reasons. Reference "
                f"block {failed_at_blockhash} {failed_at_blocknumber}."
            )

    def set_total_withdraw(
        self,
        given_block_identifier: BlockIdentifier,
        channel_identifier: ChannelID,
        partner: Address,
        withdraw_input: WithdrawInput,
    ) -> TransactionHash:
        """Set total token withdraw in the channel to total_withdraw.

        Raises:
            ValueError: If provided total_withdraw is not an integer value.
        """
        total_withdraw = withdraw_input.total_withdraw
        initiator = withdraw_input.initiator
        partner_signature = withdraw_input.partner_signature
        initiator_signature = withdraw_input.initiator_signature
        expiration_block = withdraw_input.expiration_block

        if not isinstance(total_withdraw, int):
            raise ValueError("total_withdraw needs to be an integer number.")

        if total_withdraw <= 0:
            raise ValueError("total_withdraw should be larger than zero.")

        # `channel_operations_lock` is used to serialize conflicting channel
        # operations. E.g. this withdraw and a close.
        with self.channel_operations_lock[partner]:
            try:
                channel_onchain_detail = self._detail_channel(
                    participant1=initiator,
                    participant2=partner,
                    block_identifier=given_block_identifier,
                    channel_identifier=channel_identifier,
                )
                our_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=initiator,
                    partner=partner,
                    block_identifier=given_block_identifier,
                )
                partner_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=partner,
                    partner=initiator,
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
                if channel_onchain_detail.state != ChannelState.OPENED:
                    msg = (
                        f"The channel was not opened at the provided block "
                        f"({format_block_id(given_block_identifier)}). This call "
                        f"should never have been attempted."
                    )
                    raise RaidenUnrecoverableError(msg)

                if our_details.withdrawn >= total_withdraw:
                    msg = (
                        f"The provided total_withdraw amount on-chain is "
                        f"{our_details.withdrawn}. Requested total withdraw "
                        f"{total_withdraw} did not increase."
                    )
                    raise WithdrawMismatch(msg)

                total_channel_deposit = our_details.deposit + partner_details.deposit
                total_channel_withdraw = total_withdraw + partner_details.withdrawn
                if total_channel_withdraw > total_channel_deposit:
                    msg = (
                        f"The total channel withdraw amount "
                        f"{total_channel_withdraw} is larger than the total channel "
                        f"deposit of {total_channel_deposit}."
                    )
                    raise WithdrawMismatch(msg)

                if expiration_block <= given_block_number:
                    msg = (
                        f"The current block number {given_block_number} is "
                        f"already at expiration block {expiration_block} or "
                        "later."
                    )
                    raise BrokenPreconditionError(msg)

                if initiator_signature == EMPTY_SIGNATURE:
                    msg = "set_total_withdraw requires a valid participant signature"
                    raise RaidenUnrecoverableError(msg)

                if partner_signature == EMPTY_SIGNATURE:
                    msg = "set_total_withdraw requires a valid partner signature"
                    raise RaidenUnrecoverableError(msg)

                canonical_identifier = CanonicalIdentifier(
                    chain_identifier=self.proxy.functions.chain_id().call(),
                    token_network_address=self.address,
                    channel_identifier=channel_identifier,
                )
                participant_signed_data = pack_withdraw(
                    participant=initiator,
                    total_withdraw=total_withdraw,
                    canonical_identifier=canonical_identifier,
                    expiration_block=expiration_block,
                )
                try:
                    participant_recovered_address = recover(
                        data=participant_signed_data, signature=initiator_signature
                    )
                except Exception:  # pylint: disable=broad-except
                    raise RaidenUnrecoverableError(
                        "Couldn't verify the initiator withdraw signature"
                    )
                else:
                    if participant_recovered_address != initiator:
                        raise RaidenUnrecoverableError("Invalid withdraw initiator signature")

                partner_signed_data = pack_withdraw(
                    participant=initiator,
                    total_withdraw=total_withdraw,
                    canonical_identifier=canonical_identifier,
                    expiration_block=expiration_block,
                )
                try:
                    partner_recovered_address = recover(
                        data=partner_signed_data, signature=partner_signature
                    )
                except Exception:  # pylint: disable=broad-except
                    raise RaidenUnrecoverableError(
                        "Couldn't verify the partner withdraw signature"
                    )
                else:
                    if partner_recovered_address != partner:
                        raise RaidenUnrecoverableError("Invalid withdraw partner signature")

            log_details = {"given_block_identifier": format_block_id(given_block_identifier)}

            return self._set_total_withdraw(
                channel_identifier=channel_identifier,
                total_withdraw=total_withdraw,
                expiration_block=expiration_block,
                participant=initiator,
                partner=partner,
                partner_signature=partner_signature,
                participant_signature=initiator_signature,
                log_details=log_details,
            )

    def _set_total_withdraw(
        self,
        channel_identifier: ChannelID,
        total_withdraw: WithdrawAmount,
        expiration_block: BlockExpiration,
        participant: Address,
        partner: Address,
        partner_signature: Signature,
        participant_signature: Signature,
        log_details: Dict[Any, Any],
    ) -> TransactionHash:

        estimated_transaction = self.client.estimate_gas(
            self.proxy,
            "setTotalWithdraw",
            extra_log_details=log_details,
            channel_identifier=channel_identifier,
            participant=participant,
            total_withdraw=total_withdraw,
            expiration_block=expiration_block,
            partner_signature=partner_signature,
            participant_signature=participant_signature,
        )

        if estimated_transaction is not None:
            estimated_transaction.estimated_gas = safe_gas_limit(
                estimated_transaction.estimated_gas,
                self.metadata.gas_measurements["TokenNetwork.setTotalWithdraw"],
            )

            transaction_sent = self.client.transact(estimated_transaction)
            transaction_mined = self.client.poll_transaction(transaction_sent)

            if not was_transaction_successfully_mined(transaction_mined):
                receipt = transaction_mined.receipt
                # Because the gas estimation succeeded it is known that:
                # - The channel was open.
                # - The total withdraw amount increased.
                # - The account had enough balance to pay for the gas (however
                #   there is a race condition for multiple transactions #3890)

                failed_at_blockhash = encode_hex(receipt["blockHash"])
                failed_at_blocknumber = receipt["blockNumber"]

                check_transaction_failure(transaction_mined, self.client)

                # Query the current state to check for transaction races
                detail = self._detail_channel(
                    participant1=participant,
                    participant2=partner,
                    block_identifier=failed_at_blockhash,
                    channel_identifier=channel_identifier,
                )
                our_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=participant,
                    partner=partner,
                    block_identifier=failed_at_blockhash,
                )
                partner_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=partner,
                    partner=participant,
                    block_identifier=failed_at_blockhash,
                )

                total_withdraw_done = our_details.withdrawn >= total_withdraw
                if total_withdraw_done:
                    raise RaidenRecoverableError("Requested total withdraw was already performed")

                if detail.state > ChannelState.OPENED:
                    msg = (
                        f"setTotalWithdraw failed because the channel closed "
                        f"before the transaction was mined. "
                        f"current_state={detail.state}"
                    )
                    raise RaidenRecoverableError(msg)

                if detail.state < ChannelState.OPENED:
                    msg = (
                        f"setTotalWithdraw failed because the channel never "
                        f"existed. current_state={detail.state}"
                    )
                    raise RaidenUnrecoverableError(msg)

                if expiration_block <= failed_at_blocknumber:
                    msg = (
                        f"setTotalWithdraw failed because the transaction was "
                        f"mined after the withdraw expired "
                        f"expiration_block={expiration_block} "
                        f"transation_mined_at={failed_at_blocknumber}"
                    )
                    raise RaidenRecoverableError(msg)

                total_channel_deposit = our_details.deposit + partner_details.deposit
                total_channel_withdraw = total_withdraw + partner_details.withdrawn
                if total_channel_withdraw > total_channel_deposit:
                    msg = (
                        f"The total channel withdraw amount "
                        f"{total_channel_withdraw} became larger than the total channel "
                        f"deposit of {total_channel_deposit}."
                    )
                    raise WithdrawMismatch(msg)

                raise RaidenUnrecoverableError("SetTotalwithdraw failed for an unknown reason")
            else:
                return transaction_mined.transaction_hash
        else:
            # The transaction would have failed if sent, figure out why.

            # The latest block can not be used reliably because of reorgs,
            # therefore every call using this block has to handle pruned data.
            failed_at = self.client.get_block(BLOCK_ID_LATEST)
            failed_at_blockhash = encode_hex(failed_at["hash"])
            failed_at_blocknumber = failed_at["number"]

            self.client.check_for_insufficient_eth(
                transaction_name="total_withdraw",
                transaction_executed=False,
                required_gas=self.metadata.gas_measurements["TokenNetwork.setTotalWithdraw"],
                block_identifier=failed_at_blocknumber,
            )
            detail = self._detail_channel(
                participant1=participant,
                participant2=partner,
                block_identifier=failed_at_blockhash,
                channel_identifier=channel_identifier,
            )
            our_details = self._detail_participant(
                channel_identifier=channel_identifier,
                detail_for=participant,
                partner=partner,
                block_identifier=failed_at_blockhash,
            )

            if detail.state > ChannelState.OPENED:
                msg = (
                    f"cannot call setTotalWithdraw on a channel that is not open. "
                    f"current_state={detail.state}"
                )
                raise RaidenRecoverableError(msg)

            if detail.state < ChannelState.OPENED:
                msg = (
                    f"cannot call setTotalWithdraw on a channel that does not exist. "
                    f"current_state={detail.state}"
                )
                raise RaidenUnrecoverableError(msg)

            if expiration_block <= failed_at_blocknumber:
                msg = (
                    f"setTotalWithdraw would have failed because current block "
                    f"has already reached the withdraw expiration "
                    f"expiration_block={expiration_block} "
                    f"transation_checked_at={failed_at_blocknumber}"
                )
                raise RaidenRecoverableError(msg)

            total_withdraw_done = our_details.withdrawn >= total_withdraw
            if total_withdraw_done:
                raise RaidenRecoverableError("Requested total withdraw was already performed")

            raise RaidenUnrecoverableError(
                f"setTotalWithdraw gas estimation failed for an unknown reason. "
                f"Reference block {failed_at_blockhash} {failed_at_blocknumber}."
            )

    def coop_settle(
        self,
        channel_identifier: ChannelID,
        withdraw_initiator: WithdrawInput,
        withdraw_partner: WithdrawInput,
        given_block_identifier: BlockIdentifier,
    ) -> TransactionHash:
        #  Don't duplicate all the verification of the contracts here for now,
        #  since we very soon will have revert-string feedback from the contracts,
        #  and will get rid of the `proxies` module altogether.
        #  Not having this is no security flaw, we just  don't have good error feedback
        #  for the moment.

        log_details = {"given_block_identifier": format_block_id(given_block_identifier)}

        estimated_transaction = self.client.estimate_gas(
            self.proxy,
            "cooperativeSettle",
            extra_log_details=log_details,
            channel_identifier=channel_identifier,
            data1=tuple(withdraw_initiator),
            data2=tuple(withdraw_partner),
        )

        if estimated_transaction is None:
            raise RaidenRecoverableError("CoopSettle: gas-estimation of transaction failed.")

        estimated_transaction.estimated_gas = safe_gas_limit(
            estimated_transaction.estimated_gas,
            self.metadata.gas_measurements["TokenNetwork.cooperativeSettle"],
        )

        transaction_sent = self.client.transact(estimated_transaction)
        transaction_mined = self.client.poll_transaction(transaction_sent)

        if was_transaction_successfully_mined(transaction_mined):
            return transaction_mined.transaction_hash

        receipt = transaction_mined.receipt
        failed_at_blockhash = encode_hex(receipt["blockHash"])
        failed_at_blocknumber = receipt["blockNumber"]

        check_transaction_failure(transaction_mined, self.client)
        raise RaidenRecoverableError(
            f"CoopSettle: mining of transaction failed (block_hash={failed_at_blockhash},"
            f" block_number={failed_at_blocknumber})"
        )

    def close(
        self,
        channel_identifier: ChannelID,
        partner: Address,
        balance_hash: BalanceHash,
        nonce: Nonce,
        additional_hash: AdditionalHash,
        non_closing_signature: Signature,
        closing_signature: Signature,
        given_block_identifier: BlockIdentifier,
    ) -> TransactionHash:
        """Close the channel using the provided balance proof.

        Note:
            This method must *not* be called without updating the application
            state, otherwise the node may accept new transfers which cannot be
            used, because the closer is not allowed to update the balance proof
            submitted on chain after closing

        Raises:
            RaidenRecoverableError: If the close call failed but it is not
                critical.
            RaidenUnrecoverableError: If the operation was illegal at the
                `given_block_identifier` or if the channel changes in a way that
                cannot be recovered.
        """

        canonical_identifier = CanonicalIdentifier(
            chain_identifier=self.proxy.functions.chain_id().call(),
            token_network_address=self.address,
            channel_identifier=channel_identifier,
        )

        our_signed_data = pack_signed_balance_proof(
            msg_type=MessageTypeId.BALANCE_PROOF,
            nonce=nonce,
            balance_hash=balance_hash,
            additional_hash=additional_hash,
            canonical_identifier=canonical_identifier,
            partner_signature=non_closing_signature,
        )
        try:
            our_recovered_address = recover(data=our_signed_data, signature=closing_signature)
        except Exception:  # pylint: disable=broad-except
            raise RaidenUnrecoverableError("Couldn't verify the closing signature")
        else:
            if our_recovered_address != self.node_address:
                raise RaidenUnrecoverableError("Invalid closing signature")

        if non_closing_signature != EMPTY_SIGNATURE:
            partner_signed_data = pack_balance_proof(
                nonce=nonce,
                balance_hash=balance_hash,
                additional_hash=additional_hash,
                canonical_identifier=canonical_identifier,
            )
            try:
                partner_recovered_address = recover(
                    data=partner_signed_data, signature=non_closing_signature
                )

                # InvalidSignature is raised by raiden.utils.signer.recover if signature
                # is not bytes or has the incorrect length
                #
                # ValueError is raised if the PublicKey instantiation failed, let it
                # propagate because it's a memory pressure problem.
                #
                # Exception is raised if the public key recovery failed.
            except Exception:  # pylint: disable=broad-except
                raise RaidenUnrecoverableError("Couldn't verify the non-closing signature")
            else:
                if partner_recovered_address != partner:
                    raise RaidenUnrecoverableError("Invalid non-closing signature")

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
                    f"on-chain at the provided block ({format_block_id(given_block_identifier)}). "
                    f"This call should never have been attempted. "
                    f"provided_channel_identifier={channel_identifier}, "
                    f"onchain_channel_identifier={channel_onchain_detail.channel_identifier}"
                )
                raise RaidenUnrecoverableError(msg)

            if channel_onchain_detail.state != ChannelState.OPENED:
                msg = (
                    f"The channel was not open at the provided block "
                    f"({format_block_id(given_block_identifier)}). This call should never have "
                    f"been attempted."
                )
                raise RaidenUnrecoverableError(msg)

        log_details = {"given_block_identifier": format_block_id(given_block_identifier)}

        return self._close(
            channel_identifier=channel_identifier,
            partner=partner,
            balance_hash=balance_hash,
            nonce=nonce,
            additional_hash=additional_hash,
            non_closing_signature=non_closing_signature,
            closing_signature=closing_signature,
            log_details=log_details,
        )

    def _close(
        self,
        channel_identifier: ChannelID,
        partner: Address,
        balance_hash: BalanceHash,
        nonce: Nonce,
        additional_hash: AdditionalHash,
        non_closing_signature: Signature,
        closing_signature: Signature,
        log_details: Dict[Any, Any],
    ) -> TransactionHash:
        # `channel_operations_lock` is used to serialize conflicting channel
        # operations. E.g. this close and a deposit or withdraw.
        with self.channel_operations_lock[partner]:
            estimated_transaction = self.client.estimate_gas(
                self.proxy,
                "closeChannel",
                extra_log_details=log_details,
                channel_identifier=channel_identifier,
                non_closing_participant=partner,
                closing_participant=self.node_address,
                balance_hash=balance_hash,
                nonce=nonce,
                additional_hash=additional_hash,
                non_closing_signature=non_closing_signature,
                closing_signature=closing_signature,
            )

            if estimated_transaction is not None:
                estimated_transaction.estimated_gas = safe_gas_limit(
                    estimated_transaction.estimated_gas,
                    self.metadata.gas_measurements["TokenNetwork.closeChannel"],
                )
                transaction_sent = self.client.transact(estimated_transaction)
                transaction_mined = self.client.poll_transaction(transaction_sent)

                if not was_transaction_successfully_mined(transaction_mined):
                    receipt = transaction_mined.receipt
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
                    mining_block = BlockNumber(receipt["blockNumber"])

                    check_transaction_failure(transaction_mined, self.client)

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
                    return transaction_mined.transaction_hash

            else:
                # The transaction would have failed if sent, figure out why.

                # The latest block can not be used reliably because of reorgs,
                # therefore every call using this block has to handle pruned data.
                failed_at = self.client.get_block(BLOCK_ID_LATEST)
                failed_at_blockhash = encode_hex(failed_at["hash"])
                failed_at_blocknumber = failed_at["number"]

                self.client.check_for_insufficient_eth(
                    transaction_name="closeChannel",
                    transaction_executed=True,
                    required_gas=self.metadata.gas_measurements["TokenNetwork.closeChannel"],
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

                raise RaidenUnrecoverableError(
                    f"close channel gas estimation failed for an unknown "
                    f"reason. Reference block {failed_at_blockhash} "
                    f"{failed_at_blocknumber}."
                )

    def update_transfer(
        self,
        channel_identifier: ChannelID,
        partner: Address,
        balance_hash: BalanceHash,
        nonce: Nonce,
        additional_hash: AdditionalHash,
        closing_signature: Signature,
        non_closing_signature: Signature,
        given_block_identifier: BlockIdentifier,
    ) -> TransactionHash:
        if balance_hash is EMPTY_BALANCE_HASH:
            raise RaidenUnrecoverableError("update_transfer called with an empty balance_hash")

        if nonce <= 0 or nonce > UINT256_MAX:
            raise RaidenUnrecoverableError("update_transfer called with an invalid nonce")

        canonical_identifier = CanonicalIdentifier(
            chain_identifier=self.proxy.functions.chain_id().call(),
            token_network_address=self.address,
            channel_identifier=channel_identifier,
        )

        partner_signed_data = pack_balance_proof(
            nonce=nonce,
            balance_hash=balance_hash,
            additional_hash=additional_hash,
            canonical_identifier=canonical_identifier,
        )

        our_signed_data = pack_signed_balance_proof(
            msg_type=MessageTypeId.BALANCE_PROOF_UPDATE,
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
                    f"({format_block_id(given_block_identifier)}). This call should never have "
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

        log_details = {"given_block_identifier": format_block_id(given_block_identifier)}

        return self._update_transfer(
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
    ) -> TransactionHash:
        estimated_transaction = self.client.estimate_gas(
            self.proxy,
            "updateNonClosingBalanceProof",
            extra_log_details=log_details,
            channel_identifier=channel_identifier,
            closing_participant=partner,
            non_closing_participant=self.node_address,
            balance_hash=balance_hash,
            nonce=nonce,
            additional_hash=additional_hash,
            closing_signature=closing_signature,
            non_closing_signature=non_closing_signature,
        )

        if estimated_transaction is not None:
            estimated_transaction.estimated_gas = safe_gas_limit(
                estimated_transaction.estimated_gas,
                self.metadata.gas_measurements["TokenNetwork.updateNonClosingBalanceProof"],
            )
            transaction_sent = self.client.transact(estimated_transaction)
            transaction_mined = self.client.poll_transaction(transaction_sent)

            if not was_transaction_successfully_mined(transaction_mined):
                receipt = transaction_mined.receipt
                # Because the gas estimation succeeded it is known that:
                # - The channel existed.
                # - The channel was at the state closed.
                # - The partner node was the closing address.
                # - The account had enough balance to pay for the gas (however
                #   there is a race condition for multiple transactions #3890)

                # These checks do not have problems with race conditions because
                # `poll`ing waits for the transaction to be confirmed.
                mining_block = BlockNumber(receipt["blockNumber"])

                check_transaction_failure(transaction_mined, self.client)

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
                    msg = "update transfer was mined after the settlement window."
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
                return transaction_mined.transaction_hash

        else:
            # The transaction would have failed if sent, figure out why.

            # The latest block can not be used reliably because of reorgs,
            # therefore every call using this block has to handle pruned data.
            failed_at = self.client.get_block(BLOCK_ID_LATEST)
            failed_at_blockhash = encode_hex(failed_at["hash"])
            failed_at_blocknumber = failed_at["number"]

            self.client.check_for_insufficient_eth(
                transaction_name="updateNonClosingBalanceProof",
                transaction_executed=False,
                required_gas=self.metadata.gas_measurements[
                    "TokenNetwork.updateNonClosingBalanceProof"
                ],
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

            raise RaidenUnrecoverableError(
                f"update_transfer gas estimation failed for an unknown reason. "
                f"Reference block {failed_at_blockhash} {failed_at_blocknumber}."
            )

    def unlock(
        self,
        channel_identifier: ChannelID,
        sender: Address,
        receiver: Address,
        pending_locks: PendingLocksState,
        given_block_identifier: BlockIdentifier,
    ) -> TransactionHash:
        if not pending_locks:
            raise ValueError("unlock cannot be done without pending locks")

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
                    f"({format_block_id(given_block_identifier)}). This call "
                    f"should never have been attempted."
                )
                raise RaidenUnrecoverableError(msg)

            local_locksroot = compute_locksroot(pending_locks)
            if sender_details.locksroot != local_locksroot:
                msg = (
                    f"The provided locksroot ({to_hex(local_locksroot)}) "
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
            "pending_locks": pending_locks,
            "given_block_identifier": format_block_id(given_block_identifier),
        }

        return self._unlock(
            channel_identifier=channel_identifier,
            sender=sender,
            receiver=receiver,
            pending_locks=pending_locks,
            given_block_identifier=given_block_identifier,
            log_details=log_details,
        )

    def _unlock(
        self,
        channel_identifier: ChannelID,
        sender: Address,
        receiver: Address,
        pending_locks: PendingLocksState,
        given_block_identifier: BlockIdentifier,
        log_details: Dict[Any, Any],
    ) -> TransactionHash:
        leaves_packed = b"".join(pending_locks.locks)
        estimated_transaction = self.client.estimate_gas(
            self.proxy,
            "unlock",
            extra_log_details=log_details,
            channel_identifier=channel_identifier,
            receiver=receiver,
            sender=sender,
            locks=encode_hex(leaves_packed),
        )

        if estimated_transaction is not None:
            estimated_transaction.estimated_gas = safe_gas_limit(
                estimated_transaction.estimated_gas, UNLOCK_TX_GAS_LIMIT
            )

            transaction_sent = self.client.transact(estimated_transaction)
            transaction_mined = self.client.poll_transaction(transaction_sent)

            if not was_transaction_successfully_mined(transaction_mined):
                # Because the gas estimation succeeded it is known that:
                # - The channel was settled.
                # - The channel had pending locks on-chain for that participant.
                # - The account had enough balance to pay for the gas (however
                #   there is a race condition for multiple transactions #3890)

                check_transaction_failure(transaction_mined, self.client)

                # Query the current state to check for transaction races
                sender_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=sender,
                    partner=receiver,
                    block_identifier=given_block_identifier,
                )

                is_unlock_done = sender_details.locksroot == LOCKSROOT_OF_NO_LOCKS
                if is_unlock_done:
                    raise RaidenRecoverableError("The locks are already unlocked")

                raise RaidenRecoverableError("Unlocked failed for an unknown reason")
            else:
                return transaction_mined.transaction_hash
        else:
            # The transaction has failed, figure out why.

            # The latest block can not be used reliably because of reorgs,
            # therefore every call using this block has to handle pruned data.
            failed_at = self.client.get_block(BLOCK_ID_LATEST)
            failed_at_blockhash = encode_hex(failed_at["hash"])
            failed_at_blocknumber = failed_at["number"]

            self.client.check_for_insufficient_eth(
                transaction_name="unlock",
                transaction_executed=False,
                required_gas=UNLOCK_TX_GAS_LIMIT,
                block_identifier=failed_at_blocknumber,
            )
            detail = self._detail_channel(
                participant1=sender,
                participant2=receiver,
                block_identifier=failed_at_blockhash,
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

            is_unlock_done = sender_details.locksroot == LOCKSROOT_OF_NO_LOCKS
            if is_unlock_done:
                raise RaidenRecoverableError("The locks are already unlocked ")

            raise RaidenUnrecoverableError(
                f"unlock estimation failed for an unknown reason. Reference "
                f"block {failed_at_blockhash} {failed_at_blocknumber}."
            )

    def settle(
        self,
        channel_identifier: ChannelID,
        transferred_amount: TokenAmount,
        locked_amount: LockedAmount,
        locksroot: Locksroot,
        partner: Address,
        partner_transferred_amount: TokenAmount,
        partner_locked_amount: LockedAmount,
        partner_locksroot: Locksroot,
        given_block_identifier: BlockIdentifier,
    ) -> TransactionHash:
        # `channel_operations_lock` is used to serialize conflicting channel
        # operations. E.g. this settle and a channel open.
        with self.channel_operations_lock[partner]:
            try:
                channel_onchain_detail = self._detail_channel(
                    participant1=self.node_address,
                    participant2=partner,
                    block_identifier=given_block_identifier,
                    channel_identifier=channel_identifier,
                )
                our_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=self.node_address,
                    partner=partner,
                    block_identifier=given_block_identifier,
                )
                partner_details = self._detail_participant(
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
                if channel_identifier != channel_onchain_detail.channel_identifier:
                    msg = (
                        f"The provided channel identifier {channel_identifier} "
                        f"does not match onchain channel_identifier "
                        f"{channel_onchain_detail.channel_identifier}."
                    )
                    raise BrokenPreconditionError(msg)

                if given_block_number < channel_onchain_detail.settle_block_number:
                    msg = (
                        "settle cannot be called before the settlement "
                        "period ends, this call should never have been attempted."
                    )
                    raise BrokenPreconditionError(msg)

                if channel_onchain_detail.state != ChannelState.CLOSED:
                    msg = (
                        f"The channel was not closed at the provided block "
                        f"({format_block_id(given_block_identifier)}). This call "
                        f"should never have been attempted."
                    )
                    raise BrokenPreconditionError(msg)

                our_balance_hash = hash_balance_data(
                    transferred_amount=transferred_amount,
                    locked_amount=locked_amount,
                    locksroot=locksroot,
                )
                partner_balance_hash = hash_balance_data(
                    transferred_amount=partner_transferred_amount,
                    locked_amount=partner_locked_amount,
                    locksroot=partner_locksroot,
                )

                if our_details.balance_hash != our_balance_hash:
                    msg = "Our balance hash does not match the on-chain value"
                    raise BrokenPreconditionError(msg)

                if partner_details.balance_hash != partner_balance_hash:
                    msg = "Partner balance hash does not match the on-chain value"
                    raise BrokenPreconditionError(msg)

            log_details = {"given_block_identifier": format_block_id(given_block_identifier)}
            return self._settle(
                channel_identifier=channel_identifier,
                transferred_amount=transferred_amount,
                locked_amount=locked_amount,
                locksroot=locksroot,
                partner=partner,
                partner_transferred_amount=partner_transferred_amount,
                partner_locked_amount=partner_locked_amount,
                partner_locksroot=partner_locksroot,
                log_details=log_details,
            )

    def _settle(
        self,
        channel_identifier: ChannelID,
        transferred_amount: TokenAmount,
        locked_amount: LockedAmount,
        locksroot: Locksroot,
        partner: Address,
        partner_transferred_amount: TokenAmount,
        partner_locked_amount: LockedAmount,
        partner_locksroot: Locksroot,
        log_details: Dict[Any, Any],
    ) -> TransactionHash:

        # The second participant transferred + locked amount must be higher
        our_maximum = transferred_amount + locked_amount
        partner_maximum = partner_transferred_amount + partner_locked_amount
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

        estimated_transaction = self.client.estimate_gas(
            self.proxy,
            "settleChannel",
            extra_log_details=log_details,
            channel_identifier=channel_identifier,
            **kwargs,
        )

        if estimated_transaction is not None:
            estimated_transaction.estimated_gas = safe_gas_limit(
                estimated_transaction.estimated_gas,
                self.metadata.gas_measurements["TokenNetwork.settleChannel"],
            )

            transaction_sent = self.client.transact(estimated_transaction)
            transaction_mined = self.client.poll_transaction(transaction_sent)

            if not was_transaction_successfully_mined(transaction_mined):
                receipt = transaction_mined.receipt
                failed_at_blockhash = encode_hex(receipt["blockHash"])
                failed_at_blocknumber = BlockNumber(receipt["blockNumber"])

                self.client.check_for_insufficient_eth(
                    transaction_name="settleChannel",
                    transaction_executed=True,
                    required_gas=self.metadata.gas_measurements["TokenNetwork.settleChannel"],
                    block_identifier=failed_at_blocknumber,
                )

                channel_onchain_detail = self._detail_channel(
                    participant1=self.node_address,
                    participant2=partner,
                    block_identifier=failed_at_blockhash,
                    channel_identifier=channel_identifier,
                )
                our_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=self.node_address,
                    partner=partner,
                    block_identifier=failed_at_blockhash,
                )
                partner_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=partner,
                    partner=self.node_address,
                    block_identifier=failed_at_blockhash,
                )

                our_balance_hash = hash_balance_data(
                    transferred_amount=transferred_amount,
                    locked_amount=locked_amount,
                    locksroot=locksroot,
                )
                partner_balance_hash = hash_balance_data(
                    transferred_amount=partner_transferred_amount,
                    locked_amount=partner_locked_amount,
                    locksroot=partner_locksroot,
                )

                # The channel_identifier and the address of the participants
                # can not be verified because querying for the open event would
                # take prohibitively long (see #6106). Instead it is assumed that
                # if there is a local ChannelState instance it is properly
                # validated and the data is confirmed.

                if channel_onchain_detail.state in (ChannelState.SETTLED, ChannelState.REMOVED):
                    raise RaidenRecoverableError("Channel is already settled")

                if channel_onchain_detail.state == ChannelState.OPENED:
                    raise RaidenUnrecoverableError("Channel is still open. It cannot be settled")

                is_settle_window_over = (
                    channel_onchain_detail.state == ChannelState.CLOSED
                    and failed_at_blocknumber > channel_onchain_detail.settle_block_number
                )
                if not is_settle_window_over:
                    raise RaidenUnrecoverableError(
                        "Channel cannot be settled before settlement window is over"
                    )

                # At this point, we are certain that the channel is still in
                # CLOSED state. Therefore, on-chain balance_hashes being
                # different than the provided ones should not happen.
                if our_details.balance_hash != our_balance_hash:
                    msg = "Our balance hash does not match the on-chain value"
                    raise RaidenUnrecoverableError(msg)

                if partner_details.balance_hash != partner_balance_hash:
                    msg = "Partner balance hash does not match the on-chain value"
                    raise RaidenUnrecoverableError(msg)

                raise RaidenRecoverableError("Settle failed for an unknown reason")
            else:
                return transaction_mined.transaction_hash
        else:
            # The latest block can not be used reliably because of reorgs,
            # therefore every call using this block has to handle pruned data.
            failed_at = self.client.get_block(BLOCK_ID_LATEST)
            failed_at_blockhash = encode_hex(failed_at["hash"])
            failed_at_blocknumber = failed_at["number"]

            channel_onchain_detail = self._detail_channel(
                participant1=self.node_address,
                participant2=partner,
                block_identifier=failed_at_blockhash,
                channel_identifier=channel_identifier,
            )
            our_details = self._detail_participant(
                channel_identifier=channel_identifier,
                detail_for=self.node_address,
                partner=partner,
                block_identifier=failed_at_blockhash,
            )
            partner_details = self._detail_participant(
                channel_identifier=channel_identifier,
                detail_for=partner,
                partner=self.node_address,
                block_identifier=failed_at_blockhash,
            )

            our_balance_hash = hash_balance_data(
                transferred_amount=transferred_amount,
                locked_amount=locked_amount,
                locksroot=locksroot,
            )
            partner_balance_hash = hash_balance_data(
                transferred_amount=partner_transferred_amount,
                locked_amount=partner_locked_amount,
                locksroot=partner_locksroot,
            )

            # The channel_identifier and the address of the participants
            # can not be verified because querying for the open event would
            # take prohibitively long (see #6106). Instead it is assumed that
            # if there is a local ChannelState instance it is properly
            # validated and the data is confirmed.

            if channel_onchain_detail.state in (ChannelState.SETTLED, ChannelState.REMOVED):
                raise RaidenRecoverableError("Channel is already settled")

            if channel_onchain_detail.state == ChannelState.OPENED:
                raise RaidenUnrecoverableError("Channel is still open. It cannot be settled")

            is_settle_window_over = (
                channel_onchain_detail.state == ChannelState.CLOSED
                and failed_at_blocknumber > channel_onchain_detail.settle_block_number
            )
            if not is_settle_window_over:
                raise RaidenUnrecoverableError(
                    "Channel cannot be settled before settlement window is over"
                )

            # At this point, we are certain that the channel is still in
            # CLOSED state. Therefore, on-chain balance_hashes being
            # different than the provided ones should not happen.
            if our_details.balance_hash != our_balance_hash:
                msg = "Our balance hash does not match the on-chain value"
                raise RaidenUnrecoverableError(msg)

            if partner_details.balance_hash != partner_balance_hash:
                msg = "Partner balance hash does not match the on-chain value"
                raise RaidenUnrecoverableError(msg)

            raise RaidenRecoverableError(
                f"Settle gas estimation failed for an unknown reason. Reference "
                f"block {failed_at_blockhash} {failed_at_blocknumber}."
            )
