from collections import defaultdict
from typing import Dict, List, NamedTuple, Optional, Tuple, Union

import structlog
from eth_utils import (
    encode_hex,
    is_binary_address,
    to_canonical_address,
    to_checksum_address,
    to_normalized_address,
)
from gevent.event import AsyncResult
from gevent.lock import RLock, Semaphore

from raiden.constants import GENESIS_BLOCK_NUMBER, UNLOCK_TX_GAS_LIMIT
from raiden.exceptions import (
    ChannelOutdatedError,
    DepositMismatch,
    DuplicatedChannelError,
    InvalidAddress,
    InvalidSettleTimeout,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
    SamePeerAddress,
)
from raiden.network.proxies import Token
from raiden.network.proxies.utils import compare_contract_versions
from raiden.network.rpc.client import StatelessFilter, check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.transfer.balance_proof import pack_balance_proof
from raiden.utils import pex, safe_gas_limit
from raiden.utils.signer import recover
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    BalanceHash,
    BlockNumber,
    BlockSpecification,
    ChainID,
    ChannelID,
    Locksroot,
    MerkleTreeLeaves,
    Nonce,
    Signature,
    T_ChannelID,
    T_ChannelState,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkID,
)
from raiden_contracts.constants import (
    CONTRACT_TOKEN_NETWORK,
    GAS_REQUIRED_FOR_CLOSE_CHANNEL,
    GAS_REQUIRED_FOR_OPEN_CHANNEL,
    GAS_REQUIRED_FOR_SET_TOTAL_DEPOSIT,
    GAS_REQUIRED_FOR_SETTLE_CHANNEL,
    GAS_REQUIRED_FOR_UPDATE_BALANCE_PROOF,
    ChannelInfoIndex,
    ChannelState,
    ParticipantInfoIndex,
)
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


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
    channel_data: int
    participants_data: ParticipantsDetails


class TokenNetwork:
    def __init__(
            self,
            jsonrpc_client,
            token_network_address: TokenNetworkAddress,
            contract_manager: ContractManager,
    ):
        if not is_binary_address(token_network_address):
            raise InvalidAddress('Expected binary address format for token nework')

        check_address_has_code(
            jsonrpc_client,
            Address(token_network_address),
            CONTRACT_TOKEN_NETWORK,
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
        self.open_channel_transactions = dict()

        # Forbids concurrent operations on the same channel
        self.channel_operations_lock = defaultdict(RLock)

        # Serializes concurent deposits on this token network. This must be an
        # exclusive lock, since we need to coordinate the approve and
        # setTotalDeposit calls.
        self.deposit_lock = Semaphore()

    def _call_and_check_result(
            self,
            block_identifier: BlockSpecification,
            function_name: str,
            *args,
    ):
        fn = getattr(self.proxy.contract.functions, function_name)
        call_result = fn(*args).call(block_identifier=block_identifier)

        if call_result == b'':
            raise RuntimeError(f"Call to '{function_name}' returned nothing")

        return call_result

    def token_address(self) -> Address:
        """ Return the token of this manager. """
        return to_canonical_address(self.proxy.contract.functions.token().call())

    def _new_channel_preconditions(
            self,
            partner: Address,
            settle_timeout: int,
            block_identifier: BlockSpecification,
    ):
        if not is_binary_address(partner):
            raise InvalidAddress('Expected binary address format for channel partner')

        invalid_timeout = (
            settle_timeout < self.settlement_timeout_min() or
            settle_timeout > self.settlement_timeout_max()
        )
        if invalid_timeout:
            raise InvalidSettleTimeout('settle_timeout must be in range [{}, {}], is {}'.format(
                self.settlement_timeout_min(),
                self.settlement_timeout_max(),
                settle_timeout,
            ))

        if self.node_address == partner:
            raise SamePeerAddress('The other peer must not have the same address as the client.')

        channel_exists = self.channel_exists_and_not_settled(
            participant1=self.node_address,
            participant2=partner,
            block_identifier=block_identifier,
        )
        if channel_exists:
            raise DuplicatedChannelError('Channel with given partner address already exists')

    def _new_channel_postconditions(
            self,
            partner: Address,
            block: BlockSpecification,
    ):
        channel_created = self.channel_exists_and_not_settled(
            participant1=self.node_address,
            participant2=partner,
            block_identifier=block,
        )
        if channel_created:
            raise DuplicatedChannelError('Channel with given partner address already exists')

    def new_netting_channel(
            self,
            partner: Address,
            settle_timeout: int,
            given_block_identifier: BlockSpecification,
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
        self._new_channel_preconditions(partner, settle_timeout, given_block_identifier)
        log_details = {
            'peer1': pex(self.node_address),
            'peer2': pex(partner),
        }
        gas_limit = self.proxy.estimate_gas(
            checking_block,
            'openChannel',
            self.node_address,
            partner,
            settle_timeout,
        )
        if not gas_limit:
            self.proxy.jsonrpc_client.check_for_insufficient_eth(
                transaction_name='openChannel',
                transaction_executed=False,
                required_gas=GAS_REQUIRED_FOR_OPEN_CHANNEL,
                block_identifier=checking_block,
            )
            self._new_channel_postconditions(
                partner=partner,
                block='pending',
            )

            log.critical('new_netting_channel call will fail', **log_details)
            raise RaidenUnrecoverableError('Creating a new channel will fail')

        log.debug('new_netting_channel called', **log_details)
        # Prevent concurrent attempts to open a channel with the same token and
        # partner address.
        if gas_limit and partner not in self.open_channel_transactions:
            new_open_channel_transaction = AsyncResult()
            self.open_channel_transactions[partner] = new_open_channel_transaction
            gas_limit = safe_gas_limit(gas_limit, GAS_REQUIRED_FOR_OPEN_CHANNEL)
            try:
                transaction_hash = self.proxy.transact(
                    'openChannel',
                    gas_limit,
                    self.node_address,
                    partner,
                    settle_timeout,
                )
                self.client.poll(transaction_hash)
                receipt_or_none = check_transaction_threw(self.client, transaction_hash)
                if receipt_or_none:
                    self._new_channel_postconditions(
                        partner=partner,
                        block=receipt_or_none['blockNumber'],
                    )
                    log.critical('new_netting_channel failed', **log_details)
                    raise RaidenUnrecoverableError('creating new channel failed')

            except Exception as e:
                log.critical('new_netting_channel failed', **log_details)
                new_open_channel_transaction.set_exception(e)
                raise
            else:
                new_open_channel_transaction.set(transaction_hash)
            finally:
                self.open_channel_transactions.pop(partner, None)
        else:
            # All other concurrent threads should block on the result of opening this channel
            self.open_channel_transactions[partner].get()

        channel_identifier: ChannelID = self.detail_channel(
            participant1=self.node_address,
            participant2=partner,
            block_identifier='latest',
        ).channel_identifier
        log_details['channel_identifier'] = str(channel_identifier)
        log.info('new_netting_channel successful', **log_details)

        return channel_identifier

    def _inspect_channel_identifier(
            self,
            participant1: Address,
            participant2: Address,
            called_by_fn: str,
            block_identifier: BlockSpecification,
            channel_identifier: ChannelID = None,
    ) -> ChannelID:
        if not channel_identifier:
            channel_identifier = self.proxy.contract.functions.getChannelIdentifier(
                to_checksum_address(participant1),
                to_checksum_address(participant2),
            ).call(block_identifier=block_identifier)

        if not isinstance(channel_identifier, T_ChannelID):
            raise ValueError('channel_identifier must be of type T_ChannelID')

        if channel_identifier == 0:
            raise RaidenRecoverableError(
                f'When calling {called_by_fn} either 0 value was given for the '
                'channel_identifier or getChannelIdentifier returned 0, meaning '
                f'no channel currently exists between {pex(participant1)} and '
                f'{pex(participant2)}',
            )

        return channel_identifier

    def channel_exists_and_not_settled(
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
            channel_state > ChannelState.NONEXISTENT and
            channel_state < ChannelState.SETTLED
        )
        return exists_and_not_settled

    def detail_participant(
            self,
            channel_identifier: ChannelID,
            participant: Address,
            partner: Address,
            block_identifier: BlockSpecification,
    ) -> ParticipantDetails:
        """ Returns a dictionary with the channel participant information. """

        data = self._call_and_check_result(
            block_identifier,
            'getChannelParticipantInfo',
            channel_identifier,
            to_checksum_address(participant),
            to_checksum_address(partner),
        )
        return ParticipantDetails(
            address=participant,
            deposit=data[ParticipantInfoIndex.DEPOSIT],
            withdrawn=data[ParticipantInfoIndex.WITHDRAWN],
            is_closer=data[ParticipantInfoIndex.IS_CLOSER],
            balance_hash=data[ParticipantInfoIndex.BALANCE_HASH],
            nonce=data[ParticipantInfoIndex.NONCE],
            locksroot=data[ParticipantInfoIndex.LOCKSROOT],
            locked_amount=data[ParticipantInfoIndex.LOCKED_AMOUNT],
        )

    def detail_channel(
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
        channel_identifier = self._inspect_channel_identifier(
            participant1=participant1,
            participant2=participant2,
            called_by_fn='detail_channel',
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )

        channel_data = self._call_and_check_result(
            block_identifier,
            'getChannelInfo',
            channel_identifier,
            to_checksum_address(participant1),
            to_checksum_address(participant2),
        )

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
            raise ValueError('One participant must be the node address')

        if self.node_address == participant2:
            participant1, participant2 = participant2, participant1

        channel_identifier = self._inspect_channel_identifier(
            participant1=participant1,
            participant2=participant2,
            called_by_fn='details_participants',
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )

        our_data = self.detail_participant(
            channel_identifier=channel_identifier,
            participant=participant1,
            partner=participant2,
            block_identifier=block_identifier,
        )
        partner_data = self.detail_participant(
            channel_identifier=channel_identifier,
            participant=participant2,
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
            raise ValueError('One participant must be the node address')

        if self.node_address == participant2:
            participant1, participant2 = participant2, participant1

        channel_data = self.detail_channel(
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
            chain_id=chain_id,
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

    def closing_address(
            self,
            participant1: Address,
            participant2: Address,
            block_identifier: BlockSpecification,
            channel_identifier: ChannelID = None,
    ) -> Optional[Address]:
        """ Returns the address of the closer, if the channel is closed and not settled. None
        otherwise. """

        try:
            channel_data = self.detail_channel(
                participant1=participant1,
                participant2=participant2,
                block_identifier=block_identifier,
                channel_identifier=channel_identifier,
            )
        except RaidenRecoverableError:
            return None

        if channel_data.state >= ChannelState.SETTLED:
            return None

        participants_data = self.detail_participants(
            participant1=participant1,
            participant2=participant2,
            block_identifier=block_identifier,
            channel_identifier=channel_data.channel_identifier,
        )

        if participants_data.our_details.is_closer:
            return participants_data.our_details.address
        elif participants_data.partner_details.is_closer:
            return participants_data.partner_details.address

        return None

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

        deposit = self.detail_participant(
            channel_identifier=channel_identifier,
            participant=participant1,
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
            block_identifier: BlockSpecification,
    ) -> Tuple[TokenAmount, Dict]:
        if not isinstance(total_deposit, int):
            raise ValueError('total_deposit needs to be an integral number.')

        self._check_for_outdated_channel(
            participant1=self.node_address,
            participant2=partner,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )

        # setTotalDeposit requires a monotonically increasing value. This
        # is used to handle concurrent actions:
        #
        #  - The deposits will be done in order, i.e. the monotonic
        #  property is preserved by the caller
        #  - The race of two deposits will be resolved with the larger
        #  deposit winning
        #  - Retries wont have effect
        #
        # This check is serialized with the channel_operations_lock to avoid
        # sending invalid transactions on-chain (decreasing total deposit).
        #
        previous_total_deposit = self.detail_participant(
            channel_identifier=channel_identifier,
            participant=self.node_address,
            partner=partner,
            block_identifier=block_identifier,
        ).deposit
        amount_to_deposit = total_deposit - previous_total_deposit

        log_details = {
            'token_network': pex(self.address),
            'channel_identifier': channel_identifier,
            'node': pex(self.node_address),
            'partner': pex(partner),
            'new_total_deposit': total_deposit,
            'previous_total_deposit': previous_total_deposit,
        }

        # These two scenarios can happen if two calls to deposit happen
        # and then we get here on the second call
        if total_deposit < previous_total_deposit:
            msg = (
                f'Current total deposit ({previous_total_deposit}) is already larger '
                f'than the requested total deposit amount ({total_deposit})'
            )
            log.info('setTotalDeposit failed', reason=msg, **log_details)
            raise DepositMismatch(msg)

        if amount_to_deposit <= 0:
            msg = (
                f'new_total_deposit - previous_total_deposit must be greater than 0. '
                f'new_total_deposit={total_deposit} '
                f'previous_total_deposit={previous_total_deposit}'
            )
            log.info('setTotalDeposit failed', reason=msg, **log_details)
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
                f'new_total_deposit - previous_total_deposit =  {amount_to_deposit} can not '
                f'be larger than the available balance {current_balance}, '
                f'for token at address {pex(token.address)}'
            )
            log.info('setTotalDeposit failed', reason=msg, **log_details)
            raise DepositMismatch(msg)

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
        #  making the second deposit fail.
        token.approve(
            allowed_address=Address(self.address),
            allowance=amount_to_deposit,
            given_block_identifier=block_identifier,
        )

        return amount_to_deposit, log_details

    def set_total_deposit(
            self,
            given_block_identifier: BlockSpecification,
            channel_identifier: ChannelID,
            total_deposit: TokenAmount,
            partner: Address,
    ):
        """ Set total token deposit in the channel to total_deposit.

        Raises:
            ChannelBusyError: If the channel is busy with another operation
            RuntimeError: If the token address is empty.
        """
        token_address = self.token_address()
        token = Token(
            jsonrpc_client=self.client,
            token_address=token_address,
            contract_manager=self.contract_manager,
        )
        checking_block = self.client.get_checking_block()
        error_prefix = 'setTotalDeposit call will fail'
        with self.channel_operations_lock[partner], self.deposit_lock:
            amount_to_deposit, log_details = self._deposit_preconditions(
                channel_identifier=channel_identifier,
                total_deposit=total_deposit,
                partner=partner,
                token=token,
                block_identifier=given_block_identifier,
            )

            gas_limit = self.proxy.estimate_gas(
                checking_block,
                'setTotalDeposit',
                channel_identifier,
                self.node_address,
                total_deposit,
                partner,
            )

            if gas_limit:
                gas_limit = safe_gas_limit(gas_limit, GAS_REQUIRED_FOR_SET_TOTAL_DEPOSIT)
                error_prefix = 'setTotalDeposit call failed'

                log.debug('setTotalDeposit called', **log_details)
                transaction_hash = self.proxy.transact(
                    'setTotalDeposit',
                    gas_limit,
                    channel_identifier,
                    self.node_address,
                    total_deposit,
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
                    transaction_name='setTotalDeposit',
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

                error_msg = f'{error_prefix}. {msg}'
                if error_type == RaidenRecoverableError:
                    log.warning(error_msg, **log_details)
                else:
                    log.critical(error_msg, **log_details)
                raise error_type(error_msg)

            log.info('setTotalDeposit successful', **log_details)

    def _check_why_deposit_failed(
            self,
            channel_identifier: ChannelID,
            partner: Address,
            token: Token,
            amount_to_deposit: TokenAmount,
            total_deposit: TokenAmount,
            transaction_executed: bool,
            block_identifier: BlockSpecification,
    ) -> Tuple[
        Union[RaidenRecoverableError, RaidenUnrecoverableError],
        str,
    ]:
        error_type = RaidenUnrecoverableError
        msg = ''
        latest_deposit = self.detail_participant(
            channel_identifier=channel_identifier,
            participant=self.node_address,
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
                'The allowance is insufficient. Check concurrent deposits '
                'for the same token network but different proxies.'
            )
        elif token.balance_of(self.node_address, block_identifier) < amount_to_deposit:
            msg = 'The address doesnt have enough tokens'
        elif transaction_executed and latest_deposit < total_deposit:
            msg = 'The tokens were not transferred'
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
                    f'Channel between participant {self.node_address} '
                    f'and {partner} does not exist',
                )
            # Deposit was prohibited because the channel is settled
            elif channel_state == ChannelState.SETTLED:
                msg = 'Deposit is not possible due to channel being settled'
            # Deposit was prohibited because the channel is closed
            elif channel_state == ChannelState.CLOSED:
                error_type = RaidenRecoverableError
                msg = 'Channel is already closed'
            elif participant_details.our_details.deposit < total_deposit:
                msg = 'Deposit amount did not increase after deposit transaction'

        return error_type, msg

    def _close_preconditions(
            self,
            channel_identifier: ChannelID,
            partner: Address,
            block_identifier: BlockSpecification,
    ):
        self._check_for_outdated_channel(
            participant1=self.node_address,
            participant2=partner,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )

        error_type, msg = self._check_channel_state_for_close(
            participant1=self.node_address,
            participant2=partner,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )
        if error_type:
            raise error_type(msg)

    def close(
            self,
            channel_identifier: ChannelID,
            partner: Address,
            balance_hash: BalanceHash,
            nonce: Nonce,
            additional_hash: AdditionalHash,
            signature: Signature,
            given_block_identifier: BlockSpecification,
    ):
        """ Close the channel using the provided balance proof.

        Note:
            This method must *not* be called without updating the application
            state, otherwise the node may accept new transfers which cannot be
            used, because the closer is not allowed to update the balance proof
            submitted on chain after closing

        Raises:
            RaidenRecoverableError: If the channel is already closed.
            RaidenUnrecoverableError: If the channel does not exist or is settled.
        """

        log_details = {
            'token_network': pex(self.address),
            'node': pex(self.node_address),
            'partner': pex(partner),
            'nonce': nonce,
            'balance_hash': encode_hex(balance_hash),
            'additional_hash': encode_hex(additional_hash),
            'signature': encode_hex(signature),
        }
        log.debug('closeChannel called', **log_details)

        checking_block = self.client.get_checking_block()
        self._close_preconditions(
            channel_identifier,
            partner=partner,
            block_identifier=given_block_identifier,
        )

        error_prefix = 'closeChannel call will fail'
        with self.channel_operations_lock[partner]:
            gas_limit = self.proxy.estimate_gas(
                checking_block,
                'closeChannel',
                channel_identifier,
                partner,
                balance_hash,
                nonce,
                additional_hash,
                signature,
            )

            if gas_limit:
                error_prefix = 'closeChannel call failed'
                transaction_hash = self.proxy.transact(
                    'closeChannel',
                    safe_gas_limit(gas_limit, GAS_REQUIRED_FOR_CLOSE_CHANNEL),
                    channel_identifier,
                    partner,
                    balance_hash,
                    nonce,
                    additional_hash,
                    signature,
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
                    transaction_name='closeChannel',
                    transaction_executed=transaction_executed,
                    required_gas=GAS_REQUIRED_FOR_CLOSE_CHANNEL,
                    block_identifier=block,
                )
                error_type, msg = self._check_channel_state_for_close(
                    participant1=self.node_address,
                    participant2=partner,
                    block_identifier=block,
                    channel_identifier=channel_identifier,
                )
                error_msg = f'{error_prefix}. {msg}'
                if error_type == RaidenRecoverableError:
                    log.warning(error_msg, **log_details)
                else:
                    # error_type can also be None above in which case it's
                    # unknown reason why we would fail.
                    error_type = RaidenUnrecoverableError
                    log.critical(error_msg, **log_details)

                raise error_type(error_msg)

        log.info('closeChannel successful', **log_details)

    def _update_preconditions(
            self,
            channel_identifier: ChannelID,
            partner: Address,
            balance_hash: BalanceHash,
            nonce: Nonce,
            additional_hash: AdditionalHash,
            closing_signature: Signature,
            block_identifier: BlockSpecification,
    ) -> None:
        data_that_was_signed = pack_balance_proof(
            nonce=nonce,
            balance_hash=balance_hash,
            additional_hash=additional_hash,
            channel_identifier=channel_identifier,
            token_network_identifier=TokenNetworkID(self.address),
            chain_id=self.proxy.contract.functions.chain_id().call(),
        )

        try:
            signer_address = recover(
                data=data_that_was_signed,
                signature=closing_signature,
            )

            # InvalidSignature is raised by raiden.utils.signer.recover if signature
            # is not bytes or has the incorrect length
            #
            # ValueError is raised if the PublicKey instantiation failed, let it
            # propagate because it's a memory pressure problem.
            #
            # Exception is raised if the public key recovery failed.
        except Exception:  # pylint: disable=broad-except
            raise RaidenUnrecoverableError("Couldn't verify the balance proof signature")

        if signer_address != partner:
            raise RaidenUnrecoverableError('Invalid balance proof signature')

        self._check_for_outdated_channel(
            participant1=self.node_address,
            participant2=partner,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )

        detail = self.detail_channel(
            participant1=self.node_address,
            participant2=partner,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )
        if detail.state != ChannelState.CLOSED:
            raise RaidenUnrecoverableError('Channel is not in a closed state')
        elif detail.settle_block_number < self.client.block_number():
            msg = (
                'updateNonClosingBalanceProof cannot be called '
                'because the settlement period is over'
            )
            raise RaidenRecoverableError(msg)
        else:
            error_type, msg = self._check_channel_state_for_update(
                channel_identifier=channel_identifier,
                closer=partner,
                update_nonce=nonce,
                block_identifier=block_identifier,
            )
            if error_type:
                raise error_type(msg)

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
    ):
        log_details = {
            'token_network': pex(self.address),
            'node': pex(self.node_address),
            'partner': pex(partner),
            'nonce': nonce,
            'balance_hash': encode_hex(balance_hash),
            'additional_hash': encode_hex(additional_hash),
            'closing_signature': encode_hex(closing_signature),
            'non_closing_signature': encode_hex(non_closing_signature),
        }
        log.debug('updateNonClosingBalanceProof called', **log_details)

        checking_block = self.client.get_checking_block()
        self._update_preconditions(
            channel_identifier=channel_identifier,
            partner=partner,
            balance_hash=balance_hash,
            nonce=nonce,
            additional_hash=additional_hash,
            closing_signature=closing_signature,
            block_identifier=given_block_identifier,
        )

        error_prefix = 'updateNonClosingBalanceProof call will fail'
        gas_limit = self.proxy.estimate_gas(
            checking_block,
            'updateNonClosingBalanceProof',
            channel_identifier,
            partner,
            self.node_address,
            balance_hash,
            nonce,
            additional_hash,
            closing_signature,
            non_closing_signature,
        )

        if gas_limit:
            error_prefix = 'updateNonClosingBalanceProof call failed'
            transaction_hash = self.proxy.transact(
                'updateNonClosingBalanceProof',
                safe_gas_limit(gas_limit, GAS_REQUIRED_FOR_UPDATE_BALANCE_PROOF),
                channel_identifier,
                partner,
                self.node_address,
                balance_hash,
                nonce,
                additional_hash,
                closing_signature,
                non_closing_signature,
            )

            self.client.poll(transaction_hash)
            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        transaction_executed = gas_limit is not None
        if not transaction_executed or receipt_or_none:
            if transaction_executed:
                block = receipt_or_none['blockNumber']
                to_compare_block = block
            else:
                block = checking_block
                to_compare_block = self.client.block_number()

            self.proxy.jsonrpc_client.check_for_insufficient_eth(
                transaction_name='updateNonClosingBalanceProof',
                transaction_executed=transaction_executed,
                required_gas=GAS_REQUIRED_FOR_UPDATE_BALANCE_PROOF,
                block_identifier=block,
            )
            detail = self.detail_channel(
                participant1=self.node_address,
                participant2=partner,
                block_identifier=block,
                channel_identifier=channel_identifier,
            )
            if detail.settle_block_number < to_compare_block:
                error_type = RaidenRecoverableError
                msg = (
                    'updateNonClosingBalanceProof transaction '
                    'was mined after settlement finished'
                )
            else:
                error_type, msg = self._check_channel_state_for_update(
                    channel_identifier=channel_identifier,
                    closer=partner,
                    update_nonce=nonce,
                    block_identifier=block,
                )
                if error_type is None:
                    # This should never happen if the settlement window and gas price
                    # estimation is done properly
                    channel_settled = self.channel_is_settled(
                        participant1=self.node_address,
                        participant2=partner,
                        block_identifier=block,
                        channel_identifier=channel_identifier,
                    )
                    if channel_settled is True:
                        error_type = RaidenUnrecoverableError
                        msg = 'Channel is settled'
                    else:
                        error_type = RaidenUnrecoverableError
                        msg = ''

            error_msg = f'{error_prefix}. {msg}'
            if error_type == RaidenRecoverableError:
                log.warning(error_msg, **log_details)
            else:
                log.critical(error_msg, **log_details)
            raise error_type(error_msg)

        log.info('updateNonClosingBalanceProof successful', **log_details)

    def unlock(
            self,
            channel_identifier: ChannelID,
            partner: Address,
            merkle_tree_leaves: MerkleTreeLeaves,
            given_block_identifier: BlockSpecification,
    ):
        # Note: given_block_identifier
        # is unused at the moment here
        log_details = {
            'token_network': pex(self.address),
            'node': pex(self.node_address),
            'partner': pex(partner),
            'merkle_tree_leaves': merkle_tree_leaves,
        }

        if merkle_tree_leaves is None or not merkle_tree_leaves:
            log.info('skipping unlock, tree is empty', **log_details)
            return

        leaves_packed = b''.join(lock.encoded for lock in merkle_tree_leaves)

        checking_block = self.client.get_checking_block()
        error_prefix = 'Call to unlock will fail'
        gas_limit = self.proxy.estimate_gas(
            checking_block,
            'unlock',
            channel_identifier,
            self.node_address,
            partner,
            leaves_packed,
        )

        if gas_limit:
            gas_limit = safe_gas_limit(gas_limit, UNLOCK_TX_GAS_LIMIT)
            error_prefix = 'Call to unlock failed'
            log.info('unlock called', **log_details)
            transaction_hash = self.proxy.transact(
                'unlock',
                gas_limit,
                channel_identifier,
                self.node_address,
                partner,
                leaves_packed,
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
                transaction_name='unlock',
                transaction_executed=transaction_executed,
                required_gas=UNLOCK_TX_GAS_LIMIT,
                block_identifier=block,
            )
            channel_settled = self.channel_is_settled(
                participant1=self.node_address,
                participant2=partner,
                block_identifier=block,
                channel_identifier=channel_identifier,
            )
            msg = ''
            if channel_settled is False:
                msg = 'Channel is not in a settled state'

            error_msg = f'{error_prefix}. {msg}'

            log.critical(error_msg, **log_details)
            raise RaidenUnrecoverableError(error_msg)

        log.info('unlock successful', **log_details)

    def _settle_preconditions(
            self,
            channel_identifier: ChannelID,
            transferred_amount: TokenAmount,
            locked_amount: TokenAmount,
            locksroot: Locksroot,
            partner: Address,
            partner_transferred_amount: TokenAmount,
            partner_locked_amount: TokenAmount,
            partner_locksroot: Locksroot,
            block_identifier: BlockSpecification,
    ):
        self._check_for_outdated_channel(
            participant1=self.node_address,
            participant2=partner,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )

        # and now find out
        our_maximum = transferred_amount + locked_amount
        partner_maximum = partner_transferred_amount + partner_locked_amount

        # The second participant transferred + locked amount must be higher
        our_bp_is_larger = our_maximum > partner_maximum
        if our_bp_is_larger:
            return [
                partner,
                partner_transferred_amount,
                partner_locked_amount,
                partner_locksroot,
                self.node_address,
                transferred_amount,
                locked_amount,
                locksroot,
            ]
        else:
            return [
                self.node_address,
                transferred_amount,
                locked_amount,
                locksroot,
                partner,
                partner_transferred_amount,
                partner_locked_amount,
                partner_locksroot,
            ]

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
        """ Settle the channel. """
        log_details = {
            'channel_identifier': channel_identifier,
            'token_network': pex(self.address),
            'node': pex(self.node_address),
            'partner': pex(partner),
            'transferred_amount': transferred_amount,
            'locked_amount': locked_amount,
            'locksroot': encode_hex(locksroot),
            'partner_transferred_amount': partner_transferred_amount,
            'partner_locked_amount': partner_locked_amount,
            'partner_locksroot': encode_hex(partner_locksroot),
        }
        log.debug('settle called', **log_details)

        checking_block = self.client.get_checking_block()
        args = self._settle_preconditions(
            channel_identifier=channel_identifier,
            transferred_amount=transferred_amount,
            locked_amount=locked_amount,
            locksroot=locksroot,
            partner=partner,
            partner_transferred_amount=partner_transferred_amount,
            partner_locked_amount=partner_locked_amount,
            partner_locksroot=partner_locksroot,
            block_identifier=given_block_identifier,
        )

        with self.channel_operations_lock[partner]:
            error_prefix = 'Call to settle will fail'
            gas_limit = self.proxy.estimate_gas(
                checking_block,
                'settleChannel',
                channel_identifier,
                *args,
            )

            if gas_limit:
                error_prefix = 'settle call failed'
                gas_limit = safe_gas_limit(gas_limit, GAS_REQUIRED_FOR_SETTLE_CHANNEL)

                transaction_hash = self.proxy.transact(
                    'settleChannel',
                    gas_limit,
                    channel_identifier,
                    *args,
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
                transaction_name='settleChannel',
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
            error_msg = f'{error_prefix}. {msg}'
            log.critical(error_msg, **log_details)
            raise RaidenUnrecoverableError(error_msg)

        log.info('settle successful', **log_details)

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
            self.address,
            topics=topics,
            from_block=from_block,
            to_block=to_block,
        )

    def all_events_filter(
            self,
            from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
            to_block: BlockSpecification = 'latest',
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
            onchain_channel_details = self.detail_channel(
                participant1=participant1,
                participant2=participant2,
                block_identifier=block_identifier,
            )
        except RaidenRecoverableError:
            return

        onchain_channel_identifier = onchain_channel_details.channel_identifier

        if onchain_channel_identifier != channel_identifier:
            raise ChannelOutdatedError(
                'Current channel identifier is outdated. '
                f'current={channel_identifier}, '
                f'new={onchain_channel_identifier}',
            )

    def _get_channel_state(
            self,
            participant1: Address,
            participant2: Address,
            block_identifier: BlockSpecification,
            channel_identifier: ChannelID = None,
    ) -> ChannelState:
        channel_data = self.detail_channel(
            participant1=participant1,
            participant2=participant2,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )

        if not isinstance(channel_data.state, T_ChannelState):
            raise ValueError('channel state must be of type ChannelState')

        return channel_data.state

    def _check_channel_state_for_close(
            self,
            participant1: Address,
            participant2: Address,
            block_identifier: BlockSpecification,
            channel_identifier: ChannelID,
    ) -> Tuple[
        Optional[Union[RaidenRecoverableError, RaidenUnrecoverableError]],
        str,
    ]:
        error_type = None
        msg = ''
        channel_state = self._get_channel_state(
            participant1=participant1,
            participant2=participant2,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )

        if channel_state in (ChannelState.NONEXISTENT, ChannelState.REMOVED):
            error_type = RaidenUnrecoverableError
            msg = (
                f'Channel between participant {participant1} '
                f'and {participant2} does not exist',
            )
        elif channel_state == ChannelState.SETTLED:
            error_type = RaidenUnrecoverableError
            msg = 'A settled channel cannot be closed'
        elif channel_state == ChannelState.CLOSED:
            error_type = RaidenRecoverableError
            msg = 'Channel is already closed'

        return error_type, msg

    def _check_channel_state_before_settle(
            self,
            participant1: Address,
            participant2: Address,
            block_identifier: BlockSpecification,
            channel_identifier: ChannelID,
    ) -> ChannelData:

        channel_data = self.detail_channel(
            participant1=participant1,
            participant2=participant2,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )
        if channel_data.state == ChannelState.SETTLED:
            raise RaidenRecoverableError(
                'Channel is already settled',
            )
        elif channel_data.state == ChannelState.REMOVED:
            raise RaidenRecoverableError(
                'Channel is already unlocked. It cannot be settled',
            )
        elif channel_data.state == ChannelState.OPENED:
            raise RaidenUnrecoverableError(
                'Channel is still open. It cannot be settled',
            )
        elif channel_data.state == ChannelState.CLOSED:
            if self.client.block_number() < channel_data.settle_block_number:
                raise RaidenUnrecoverableError(
                    'Channel cannot be settled before settlement window is over',
                )

        return channel_data

    def _check_channel_state_after_settle(
            self,
            participant1: Address,
            participant2: Address,
            block_identifier: BlockSpecification,
            channel_identifier: ChannelID,
    ) -> str:
        msg = ''
        channel_data = self._check_channel_state_before_settle(
            participant1=participant1,
            participant2=participant2,
            block_identifier=block_identifier,
            channel_identifier=channel_identifier,
        )
        if channel_data.state == ChannelState.CLOSED:
            msg = (
                "Settling this channel failed although the channel's current state "
                "is closed.",
            )
        return msg

    def _check_channel_state_for_update(
            self,
            channel_identifier: ChannelID,
            closer: Address,
            update_nonce: Nonce,
            block_identifier: BlockSpecification,
    ) -> Tuple[Optional[RaidenRecoverableError], str]:
        """Check the channel state on chain to see if it has been updated.

        Compare the nonce we are about to update the contract with the
        updated nonce in the onchain state and if it's the same raise a
        RaidenRecoverableError"""
        error_type = None
        msg = ''
        closer_details = self.detail_participant(
            channel_identifier=channel_identifier,
            participant=closer,
            partner=self.node_address,
            block_identifier=block_identifier,
        )
        if closer_details.nonce == update_nonce:
            error_type = RaidenRecoverableError
            msg = (
                'updateNonClosingBalanceProof transaction has already '
                'been mined and updated the channel succesfully.'
            )

        return error_type, msg
