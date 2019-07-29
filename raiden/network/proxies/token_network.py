from collections import defaultdict

import structlog
from eth_utils import (
    encode_hex,
    is_binary_address,
    to_bytes,
    to_canonical_address,
    to_checksum_address,
    to_hex,
    to_normalized_address,
)
from gevent.lock import RLock
from web3.exceptions import BadFunctionCallOutput

from raiden.constants import (
    EMPTY_HASH,
    EMPTY_SIGNATURE,
    GENESIS_BLOCK_NUMBER,
    LOCKSROOT_OF_NO_LOCKS,
    NULL_ADDRESS_BYTES,
    UINT256_MAX,
    UNLOCK_TX_GAS_LIMIT,
)
from raiden.exceptions import (
    BrokenPreconditionError,
    ChannelOutdatedError,
    DepositOverLimit,
    DuplicatedChannelError,
    InvalidAddress,
    InvalidChannelID,
    InvalidSettleTimeout,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
    SamePeerAddress,
    WithdrawMismatch,
)
from raiden.network.proxies.token import Token
from raiden.network.proxies.utils import (
    get_channel_participants_from_open_event,
    log_transaction,
    raise_on_call_returned_empty,
)
from raiden.network.rpc.client import StatelessFilter, check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import PendingLocksState
from raiden.transfer.utils import hash_balance_data
from raiden.utils import safe_gas_limit
from raiden.utils.packing import pack_balance_proof, pack_signed_balance_proof, pack_withdraw
from raiden.utils.signer import recover
from raiden.utils.typing import (
    TYPE_CHECKING,
    AdditionalHash,
    Address,
    Any,
    BalanceHash,
    BlockExpiration,
    BlockNumber,
    BlockSpecification,
    ChainID,
    ChannelID,
    Dict,
    List,
    Locksroot,
    NamedTuple,
    Nonce,
    Optional,
    Signature,
    T_ChannelID,
    T_ChannelState,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    WithdrawAmount,
    typecheck,
)
from raiden_contracts.constants import (
    CONTRACT_TOKEN_NETWORK,
    ChannelInfoIndex,
    ChannelState,
    ParticipantInfoIndex,
)
from raiden_contracts.contract_manager import ContractManager, gas_measurements

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.network.blockchain_service import BlockChainService


log = structlog.get_logger(__name__)


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
    withdrawn: WithdrawAmount
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
    token_address: TokenAddress
    channel_data: ChannelData
    participants_data: ParticipantsDetails


class TokenNetwork:
    def __init__(
        self,
        jsonrpc_client,
        token_network_address: TokenNetworkAddress,
        contract_manager: ContractManager,
        blockchain_service: "BlockChainService",
    ):
        if not is_binary_address(token_network_address):
            raise InvalidAddress("Expected binary address format for token nework")

        check_address_has_code(
            jsonrpc_client,
            Address(token_network_address),
            CONTRACT_TOKEN_NETWORK,
            expected_code=to_bytes(
                hexstr=contract_manager.get_runtime_hexcode(CONTRACT_TOKEN_NETWORK)
            ),
        )

        self.contract_manager = contract_manager
        proxy = jsonrpc_client.new_contract_proxy(
            self.contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
            to_normalized_address(token_network_address),
        )

        # These are constants
        self._chain_id = proxy.contract.functions.chain_id().call()
        self._token_address = to_canonical_address(proxy.contract.functions.token().call())
        self.gas_measurements = gas_measurements(self.contract_manager.contracts_version)

        self.address = token_network_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.node_address = self.client.address

        self.token: Token = blockchain_service.token(token_address=self.token_address())

        # Forbids concurrent operations on the same channel
        self.channel_operations_lock: Dict[Address, RLock] = defaultdict(RLock)
        self.opening_channels_count = 0

    def chain_id(self) -> ChainID:
        """ Return the token of this manager. """
        return self._chain_id

    def token_address(self) -> TokenAddress:
        """ Return the token of this manager. """
        return self._token_address

    def channel_participant_deposit_limit(
        self, block_identifier: BlockSpecification
    ) -> TokenAmount:
        """ Return the deposit limit of a channel participant. """
        return TokenAmount(
            self.proxy.contract.functions.channel_participant_deposit_limit().call(
                block_identifier=block_identifier
            )
        )

    def token_network_deposit_limit(self, block_identifier: BlockSpecification) -> TokenAmount:
        """ Return the token of this manager. """
        return TokenAmount(
            self.proxy.contract.functions.token_network_deposit_limit().call(
                block_identifier=block_identifier
            )
        )

    def safety_deprecation_switch(self, block_identifier: BlockSpecification) -> bool:
        return self.proxy.contract.functions.safety_deprecation_switch().call(
            block_identifier=block_identifier
        )

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

        with self.channel_operations_lock[partner]:
            # check preconditions
            try:
                existing_channel_identifier = self.get_channel_identifier_or_none(
                    participant1=self.node_address,
                    participant2=partner,
                    block_identifier=given_block_identifier,
                )
                balance = self.token.balance_of(
                    address=to_checksum_address(self.address),
                    block_identifier=given_block_identifier,
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
                if balance >= limit:
                    raise BrokenPreconditionError(
                        "Cannot open another channel, token network deposit limit reached."
                    )
                if safety_deprecation_switch:
                    raise BrokenPreconditionError("This token network is deprecated.")

            log_details = {
                "node": to_checksum_address(self.node_address),
                "contract": to_checksum_address(self.address),
                "peer1": to_checksum_address(self.node_address),
                "peer2": to_checksum_address(partner),
                "settle_timeout": settle_timeout,
            }

            with log_transaction(log, "new_netting_channel", log_details):
                self.opening_channels_count += 1
                try:
                    channel_identifier = self._new_netting_channel(
                        partner, settle_timeout, log_details
                    )
                finally:
                    self.opening_channels_count -= 1
                log_details["channel_identifier"] = str(channel_identifier)

            return channel_identifier

    def _new_netting_channel(
        self, partner: Address, settle_timeout: int, log_details: Dict[Any, Any]
    ) -> ChannelID:
        checking_block = self.client.get_checking_block()
        gas_limit = self.proxy.estimate_gas(
            checking_block,
            "openChannel",
            participant1=self.node_address,
            participant2=partner,
            settle_timeout=settle_timeout,
        )
        if not gas_limit:
            failed_at = self.proxy.jsonrpc_client.get_block("latest")
            failed_at_blockhash = encode_hex(failed_at["hash"])
            failed_at_blocknumber = failed_at["number"]

            self.proxy.jsonrpc_client.check_for_insufficient_eth(
                transaction_name="openChannel",
                transaction_executed=False,
                required_gas=self.gas_measurements["TokenNetwork.openChannel"],
                block_identifier=failed_at_blocknumber,
            )

            existing_channel_identifier = self.get_channel_identifier_or_none(
                participant1=self.node_address,
                participant2=partner,
                block_identifier=failed_at_blockhash,
            )
            if existing_channel_identifier is not None:
                raise DuplicatedChannelError("Channel with given partner address already exists")

            balance = self.token.balance_of(
                address=to_checksum_address(self.address), block_identifier=failed_at_blockhash
            )
            limit = self.token_network_deposit_limit(block_identifier=failed_at_blockhash)
            if balance >= limit:
                raise DepositOverLimit(
                    "Could open another channel, token network deposit limit has been reached."
                )

            if self.safety_deprecation_switch(block_identifier=failed_at_blockhash):
                raise RaidenRecoverableError("This token network is deprecated.")

            raise RaidenRecoverableError(
                "Creating a new channel will fail - Gas estimation failed for unknown reason."
            )
        else:
            gas_limit = safe_gas_limit(
                gas_limit, self.gas_measurements["TokenNetwork.openChannel"]
            )
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
                failed_at_blockhash = encode_hex(receipt_or_none["blockHash"])
                existing_channel_identifier = self.get_channel_identifier_or_none(
                    participant1=self.node_address,
                    participant2=partner,
                    block_identifier=failed_at_blockhash,
                )
                if existing_channel_identifier is not None:
                    raise DuplicatedChannelError(
                        "Channel with given partner address already exists"
                    )

                balance = self.token.balance_of(
                    address=to_checksum_address(self.address), block_identifier=failed_at_blockhash
                )
                limit = self.token_network_deposit_limit(block_identifier=failed_at_blockhash)
                if balance >= limit:
                    raise DepositOverLimit(
                        "Could open another channel, token network deposit limit has been reached."
                    )

                if self.safety_deprecation_switch(block_identifier=failed_at_blockhash):
                    raise RaidenRecoverableError("This token network is deprecated.")

                raise RaidenRecoverableError("Creating new channel failed.")

        receipt = self.client.get_transaction_receipt(transaction_hash)
        channel_identifier: ChannelID = self._detail_channel(
            participant1=self.node_address,
            participant2=partner,
            block_identifier=encode_hex(receipt["blockHash"]),
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

    def get_channel_identifier_or_none(
        self, participant1: Address, participant2: Address, block_identifier: BlockSpecification
    ) -> Optional[ChannelID]:
        """ Returns the channel identifier if an open channel exists, else None. """
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
        chain_id = self.chain_id()

        return ChannelDetails(
            chain_id=chain_id,
            token_address=self.token_address(),
            channel_data=channel_data,
            participants_data=participants_data,
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

        if total_deposit <= 0 and total_deposit >= UINT256_MAX:
            msg = f"Total deposit {total_deposit} is not in range [1, {UINT256_MAX}]"
            raise BrokenPreconditionError(msg)

        # A node may be setting up multiple channels for the same token
        # concurrently. Because each deposit changes the user balance this
        # check must be serialized with the operation locks.
        #
        # The checks below are serialized with the deposit_lock to avoid sending invalid
        # transactions on-chain (account without balance). The lock
        # channel_operations_lock is not sufficient, as it allows two
        # concurrent deposits for different channels.
        with self.channel_operations_lock[partner], self.token.token_lock:
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
            except ValueError:
                # If `given_block_identifier` has been pruned the checks cannot be
                # performed.
                our_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=self.node_address,
                    partner=partner,
                    block_identifier="latest",
                )
            except BadFunctionCallOutput:
                raise_on_call_returned_empty(given_block_identifier)
            else:
                if safety_deprecation_switch:
                    msg = "This token_network has been deprecated."
                    raise BrokenPreconditionError(msg)

                if channel_onchain_detail.state != ChannelState.OPENED:
                    msg = (
                        f"The channel was not opened at the provided block "
                        f"({given_block_identifier}). This call should never have "
                        f"been attempted."
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
                if total_channel_deposit >= UINT256_MAX:
                    raise BrokenPreconditionError("Deposit overflow")

                if total_deposit > channel_participant_deposit_limit:
                    msg = (
                        f"Deposit of {total_deposit} is larger than the "
                        f"channel participant deposit limit"
                    )
                    raise BrokenPreconditionError(msg)

                network_balance = self.token.balance_of(
                    Address(self.address), given_block_identifier
                )

                if network_balance + amount_to_deposit > token_network_deposit_limit:
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
                "node": to_checksum_address(self.node_address),
                "contract": to_checksum_address(self.address),
                "participant": to_checksum_address(self.node_address),
                "receiver": to_checksum_address(partner),
                "channel_identifier": channel_identifier,
                "total_deposit": total_deposit,
                "previous_total_deposit": our_details.deposit,
            }

            with log_transaction(log, "set_total_deposit", log_details):
                self._set_total_deposit(
                    channel_identifier=channel_identifier,
                    total_deposit=total_deposit,
                    previous_total_deposit=our_details.deposit,
                    partner=partner,
                    log_details=log_details,
                )

    def _set_total_deposit(
        self,
        channel_identifier: ChannelID,
        total_deposit: TokenAmount,
        partner: Address,
        previous_total_deposit: TokenAmount,
        log_details: Dict[Any, Any],
    ) -> None:
        checking_block = self.client.get_checking_block()
        amount_to_deposit = TokenAmount(total_deposit - previous_total_deposit)

        # If there are channels being set up concurrently either the
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
        # in which case the second `approve` will overwrite the first,
        # and the first `setTotalDeposit` will consume the allowance,
        # making the second deposit fail.
        self.token.approve(allowed_address=Address(self.address), allowance=amount_to_deposit)

        gas_limit = self.proxy.estimate_gas(
            checking_block,
            "setTotalDeposit",
            channel_identifier=channel_identifier,
            participant=self.node_address,
            total_deposit=total_deposit,
            partner=partner,
        )

        if gas_limit:
            gas_limit = safe_gas_limit(
                gas_limit, self.gas_measurements["TokenNetwork.setTotalDeposit"]
            )
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
            receipt = check_transaction_threw(self.client, transaction_hash)

            if receipt:
                # Because the gas estimation succeeded it is known that:
                # - The channel was open.
                # - The account had enough tokens to deposit
                # - The account had enough balance to pay for the gas (however
                #   there is a race condition for multiple transactions #3890)
                failed_at_blockhash = encode_hex(receipt["blockHash"])
                failed_at_blocknumber = receipt["blockNumber"]

                if receipt["cumulativeGasUsed"] == gas_limit:
                    msg = (
                        f"setTotalDeposit failed and all gas was used "
                        f"({gas_limit}). Estimate gas may have underestimated "
                        f"setTotalDeposit, or succeeded even though an assert is "
                        f"triggered, or the smart contract code has an "
                        f"conditional assert."
                    )
                    raise RaidenRecoverableError(msg)

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

                channel_state = self._get_channel_state(
                    participant1=self.node_address,
                    participant2=partner,
                    block_identifier=failed_at_blockhash,
                    channel_identifier=channel_identifier,
                )
                # Check if deposit is being made on a non-open channel
                if channel_state > ChannelState.OPENED:
                    msg = "Deposit failed as the channel was not open"
                    raise RaidenRecoverableError(msg)

                deposit_amount = total_deposit - our_details.deposit

                # If an overflow is possible then we are interacting with a bad token.
                # This must not crash the client, because it is not a Raiden bug,
                # and otherwise this could be an attack vector.
                total_channel_deposit = total_deposit + partner_details.deposit
                if total_channel_deposit >= UINT256_MAX:
                    raise RaidenRecoverableError("Deposit overflow")

                total_deposit_done = our_details.deposit >= total_deposit
                if total_deposit_done:
                    raise RaidenRecoverableError("Requested total deposit was already performed")

                token_network_deposit_limit = self.token_network_deposit_limit(
                    block_identifier=receipt["blockHash"]
                )

                network_balance = self.token.balance_of(
                    address=Address(self.address), block_identifier=receipt["blockHash"]
                )

                if network_balance + deposit_amount > token_network_deposit_limit:
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

                raise RaidenRecoverableError("Unlocked failed for an unknown reason")
        else:
            # The transaction has failed, figure out why.

            # The latest block can not be used reliably because of reorgs,
            # therefore every call using this block has to handle pruned data.
            failed_at = self.proxy.jsonrpc_client.get_block("latest")
            failed_at_blockhash = encode_hex(failed_at["hash"])
            failed_at_blocknumber = failed_at["number"]

            self.proxy.jsonrpc_client.check_for_insufficient_eth(
                transaction_name="setTotalDeposit",
                transaction_executed=False,
                required_gas=self.gas_measurements["TokenNetwork.setTotalDeposit"],
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

            channel_state = self._get_channel_state(
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

            network_balance = self.token.balance_of(Address(self.address), failed_at_blocknumber)

            # Deposit was prohibited because the channel is settled
            if channel_state == ChannelState.SETTLED:
                msg = "Deposit is not possible due to channel being settled"
                raise RaidenRecoverableError(msg)

            # Deposit was prohibited because the channel is closed
            if channel_state == ChannelState.CLOSED:
                msg = "Channel is already closed"
                raise RaidenRecoverableError(msg)

            if channel_state == ChannelState.REMOVED:
                msg = "Channel was settled and unlocked"
                raise RaidenRecoverableError(msg)

            if our_details.deposit >= total_deposit:
                msg = "Attempted deposit has already been done"
                raise RaidenRecoverableError(msg)

            # Check if deposit is being made on a nonexistent channel
            if channel_state == ChannelState.NONEXISTENT:
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

            if network_balance + amount_to_deposit > token_network_deposit_limit:
                msg = (
                    f"Deposit of {amount_to_deposit} exceeded " f"the token network deposit limit."
                )
                raise RaidenRecoverableError(msg)

            raise RaidenRecoverableError("Deposit gas estimatation failed for unknown reasons")

    def set_total_withdraw(
        self,
        given_block_identifier: BlockSpecification,
        channel_identifier: ChannelID,
        total_withdraw: WithdrawAmount,
        expiration_block: BlockExpiration,
        participant_signature: Signature,
        partner_signature: Signature,
        participant: Address,
        partner: Address,
    ):
        """ Set total token withdraw in the channel to total_withdraw.

        Raises:
            ValueError: If provided total_withdraw is not an integer value.
        """
        if not isinstance(total_withdraw, int):
            raise ValueError("total_withdraw needs to be an integer number.")

        if total_withdraw <= 0:
            raise ValueError("total_withdraw should be larger than zero.")

        with self.channel_operations_lock[partner]:
            try:
                channel_onchain_detail = self._detail_channel(
                    participant1=participant,
                    participant2=partner,
                    block_identifier=given_block_identifier,
                    channel_identifier=channel_identifier,
                )
                our_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=participant,
                    partner=partner,
                    block_identifier=given_block_identifier,
                )
                partner_details = self._detail_participant(
                    channel_identifier=channel_identifier,
                    detail_for=partner,
                    partner=participant,
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
                        f"({given_block_identifier}). This call should never have "
                        f"been attempted."
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

                if participant_signature == EMPTY_SIGNATURE:
                    msg = "set_total_withdraw requires a valid participant signature"
                    raise RaidenUnrecoverableError(msg)

                if partner_signature == EMPTY_SIGNATURE:
                    msg = "set_total_withdraw requires a valid partner signature"
                    raise RaidenUnrecoverableError(msg)

                canonical_identifier = CanonicalIdentifier(
                    chain_identifier=self.proxy.contract.functions.chain_id().call(),
                    token_network_address=self.address,
                    channel_identifier=channel_identifier,
                )
                participant_signed_data = pack_withdraw(
                    participant=participant,
                    total_withdraw=total_withdraw,
                    canonical_identifier=canonical_identifier,
                    expiration_block=expiration_block,
                )
                try:
                    participant_recovered_address = recover(
                        data=participant_signed_data, signature=participant_signature
                    )
                except Exception:  # pylint: disable=broad-except
                    raise RaidenUnrecoverableError(
                        "Couldn't verify the participant withdraw signature"
                    )
                else:
                    if participant_recovered_address != participant:
                        raise RaidenUnrecoverableError("Invalid withdraw participant signature")

                partner_signed_data = pack_withdraw(
                    participant=participant,
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

            log_details = {
                "node": to_checksum_address(participant),
                "contract": to_checksum_address(self.address),
                "participant": to_checksum_address(participant),
                "partner": to_checksum_address(partner),
                "total_withdraw": total_withdraw,
            }

            with log_transaction(log, "set_total_withdraw", log_details):
                self._set_total_withdraw(
                    channel_identifier=channel_identifier,
                    total_withdraw=total_withdraw,
                    expiration_block=expiration_block,
                    participant=participant,
                    partner=partner,
                    partner_signature=partner_signature,
                    participant_signature=participant_signature,
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
    ) -> None:
        checking_block = self.client.get_checking_block()

        gas_limit = self.proxy.estimate_gas(
            checking_block,
            "setTotalWithdraw",
            channel_identifier=channel_identifier,
            participant=participant,
            total_withdraw=total_withdraw,
            expiration_block=expiration_block,
            partner_signature=partner_signature,
            participant_signature=participant_signature,
        )

        if gas_limit:
            gas_limit = safe_gas_limit(
                gas_limit, self.gas_measurements["TokenNetwork.setTotalWithdraw"]
            )
            log_details["gas_limit"] = gas_limit

            transaction_hash = self.proxy.transact(
                function_name="setTotalWithdraw",
                startgas=gas_limit,
                channel_identifier=channel_identifier,
                participant=participant,
                total_withdraw=total_withdraw,
                expiration_block=expiration_block,
                partner_signature=partner_signature,
                participant_signature=participant_signature,
            )
            self.client.poll(transaction_hash)
            receipt = check_transaction_threw(self.client, transaction_hash)

            if receipt:
                # Because the gas estimation succeeded it is known that:
                # - The channel was open.
                # - The total withdraw amount increased.
                # - The account had enough balance to pay for the gas (however
                #   there is a race condition for multiple transactions #3890)

                failed_at_blockhash = encode_hex(receipt["blockHash"])

                if receipt["cumulativeGasUsed"] == gas_limit:
                    msg = (
                        f"update transfer failed and all gas was used "
                        f"({gas_limit}). Estimate gas may have underestimated "
                        f"update transfer, or succeeded even though an assert is "
                        f"triggered, or the smart contract code has an "
                        f"conditional assert."
                    )
                    raise RaidenUnrecoverableError(msg)

                # Query the current state to check for transaction races
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
            # The transaction would have failed if sent, figure out why.

            # The latest block can not be used reliably because of reorgs,
            # therefore every call using this block has to handle pruned data.
            failed_at = self.proxy.jsonrpc_client.get_block("latest")
            failed_at_blockhash = encode_hex(failed_at["hash"])
            failed_at_blocknumber = failed_at["number"]

            self.proxy.jsonrpc_client.check_for_insufficient_eth(
                transaction_name="total_withdraw",
                transaction_executed=False,
                required_gas=self.gas_measurements["TokenNetwork.setTotalWithdraw"],
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

            if detail.state != ChannelState.OPENED:
                msg = (
                    f"cannot call setTotalWithdraw on a channel that is not open. "
                    f"current_state={detail.state}"
                )
                raise RaidenUnrecoverableError(msg)

            total_withdraw_done = our_details.withdrawn >= total_withdraw
            if total_withdraw_done:
                raise RaidenRecoverableError("Requested total withdraw was already performed")

            raise RaidenUnrecoverableError("unlock failed for an unknown reason")

    def close(
        self,
        channel_identifier: ChannelID,
        partner: Address,
        balance_hash: BalanceHash,
        nonce: Nonce,
        additional_hash: AdditionalHash,
        non_closing_signature: Signature,
        closing_signature: Signature,
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
            RaidenUnrecoverableError: If the operation was illegal at the
                `given_block_identifier` or if the channel changes in a way that
                cannot be recovered.
        """

        canonical_identifier = CanonicalIdentifier(
            chain_identifier=self.proxy.contract.functions.chain_id().call(),
            token_network_address=self.address,
            channel_identifier=channel_identifier,
        )

        our_signed_data = pack_signed_balance_proof(
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
            "non_closing_signature": encode_hex(non_closing_signature),
            "closing_signature": encode_hex(closing_signature),
        }

        with log_transaction(log, "close", log_details):
            self._close(
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
    ) -> None:
        with self.channel_operations_lock[partner]:
            checking_block = self.client.get_checking_block()
            gas_limit = self.proxy.estimate_gas(
                checking_block,
                "closeChannel",
                channel_identifier=channel_identifier,
                non_closing_participant=partner,
                closing_participant=self.node_address,
                balance_hash=balance_hash,
                nonce=nonce,
                additional_hash=additional_hash,
                non_closing_signature=non_closing_signature,
                closing_signature=closing_signature,
            )

            if gas_limit:
                gas_limit = safe_gas_limit(
                    gas_limit, self.gas_measurements["TokenNetwork.closeChannel"]
                )
                log_details["gas_limit"] = gas_limit
                transaction_hash = self.proxy.transact(
                    "closeChannel",
                    gas_limit,
                    channel_identifier=channel_identifier,
                    non_closing_participant=partner,
                    closing_participant=self.node_address,
                    balance_hash=balance_hash,
                    nonce=nonce,
                    additional_hash=additional_hash,
                    non_closing_signature=non_closing_signature,
                    closing_signature=closing_signature,
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
                    required_gas=self.gas_measurements["TokenNetwork.closeChannel"],
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

        our_signed_data = pack_signed_balance_proof(
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
            gas_limit = safe_gas_limit(
                gas_limit, self.gas_measurements["TokenNetwork.updateNonClosingBalanceProof"]
            )
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
                required_gas=self.gas_measurements["TokenNetwork.updateNonClosingBalanceProof"],
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
        pending_locks: PendingLocksState,
        given_block_identifier: BlockSpecification,
    ) -> None:
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
                    f"({given_block_identifier}). This call should never have "
                    f"been attempted."
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
            "node": to_checksum_address(self.node_address),
            "contract": to_checksum_address(self.address),
            "sender": to_checksum_address(sender),
            "receiver": to_checksum_address(receiver),
            "pending_locks": pending_locks,
        }

        with log_transaction(log, "unlock", log_details):
            self._unlock(
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
        given_block_identifier: BlockSpecification,
        log_details: Dict[Any, Any],
    ) -> None:
        checking_block = self.client.get_checking_block()
        leaves_packed = b"".join(pending_locks.locks)
        gas_limit = self.proxy.estimate_gas(
            checking_block,
            "unlock",
            channel_identifier=channel_identifier,
            receiver=receiver,
            sender=sender,
            locks=leaves_packed,
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
                locks=leaves_packed,
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
                        f"Unlock failed and all gas was used "
                        f"({gas_limit}). Estimate gas may have underestimated "
                        f"unlock, or succeeded even though an assert is "
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

                is_unlock_done = sender_details.locksroot == LOCKSROOT_OF_NO_LOCKS
                if is_unlock_done:
                    raise RaidenRecoverableError("The locks are already unlocked")

                raise RaidenRecoverableError("Unlocked failed for an unknown reason")
        else:
            # The transaction has failed, figure out why.

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

            raise RaidenUnrecoverableError("unlock failed for an unknown reason")

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
                        f"({given_block_identifier}). This call should never have "
                        f"been attempted."
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

            log_details = {
                "channel_identifier": channel_identifier,
                "contract": to_checksum_address(self.address),
                "node": to_checksum_address(self.node_address),
                "our_address": to_checksum_address(self.node_address),
                "transferred_amount": transferred_amount,
                "locked_amount": locked_amount,
                "locksroot": encode_hex(locksroot),
                "partner": to_checksum_address(partner),
                "partner_transferred_amount": partner_transferred_amount,
                "partner_locked_amount": partner_locked_amount,
                "partner_locksroot": encode_hex(partner_locksroot),
            }
            with log_transaction(log, "settle", log_details):
                self._settle(
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
        locked_amount: TokenAmount,
        locksroot: Locksroot,
        partner: Address,
        partner_transferred_amount: TokenAmount,
        partner_locked_amount: TokenAmount,
        partner_locksroot: Locksroot,
        log_details: Dict[Any, Any],
    ):
        checking_block = self.client.get_checking_block()

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

        gas_limit = self.proxy.estimate_gas(
            checking_block, "settleChannel", channel_identifier=channel_identifier, **kwargs
        )

        if gas_limit:
            gas_limit = safe_gas_limit(
                gas_limit, self.gas_measurements["TokenNetwork.settleChannel"]
            )
            log_details["gas_limit"] = gas_limit

            transaction_hash = self.proxy.transact(
                function_name="settleChannel",
                startgas=gas_limit,
                channel_identifier=channel_identifier,
                **kwargs,
            )
            self.client.poll(transaction_hash)
            receipt = check_transaction_threw(self.client, transaction_hash)

            if receipt:
                failed_at_blockhash = encode_hex(receipt["blockHash"])
                failed_at_blocknumber = receipt["blockNumber"]

                self.proxy.jsonrpc_client.check_for_insufficient_eth(
                    transaction_name="settleChannel",
                    transaction_executed=True,
                    required_gas=self.gas_measurements["TokenNetwork.settleChannel"],
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

                participants = get_channel_participants_from_open_event(
                    token_network=self,
                    channel_identifier=channel_identifier,
                    contract_manager=self.contract_manager,
                )
                if not participants:
                    msg = (
                        f"The provided channel identifier {channel_identifier} "
                        f"does not exist on-chain."
                    )
                    raise RaidenUnrecoverableError(msg)

                if self.node_address not in participants:
                    msg = (
                        f"Settling a channel in which the current node is not a participant "
                        f"of is not allowed."
                    )
                    raise RaidenUnrecoverableError(msg)

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
            # The latest block can not be used reliably because of reorgs,
            # therefore every call using this block has to handle pruned data.
            failed_at = self.proxy.jsonrpc_client.get_block("latest")
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

            participants = get_channel_participants_from_open_event(
                token_network=self,
                channel_identifier=channel_identifier,
                contract_manager=self.contract_manager,
            )
            if not participants:
                msg = (
                    f"The provided channel identifier {channel_identifier} "
                    f"does not exist on-chain."
                )
                raise RaidenUnrecoverableError(msg)

            if self.node_address not in participants:
                msg = (
                    f"Settling a channel in which the current node is not a participant "
                    f"of is not allowed."
                )
                raise RaidenUnrecoverableError(msg)

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
