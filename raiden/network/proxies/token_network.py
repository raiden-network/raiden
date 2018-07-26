from collections import defaultdict
from typing import List, Dict, Optional

import structlog
from eth_utils import (
    encode_hex,
    event_abi_to_log_topic,
    is_binary_address,
    to_canonical_address,
    to_checksum_address,
    to_normalized_address,
)
from gevent.event import AsyncResult
from gevent.lock import RLock, Semaphore
from raiden_contracts.constants import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_NONEXISTENT,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
    CONTRACT_TOKEN_NETWORK,
    EVENT_CHANNEL_OPENED,
)
from raiden_contracts.contract_manager import CONTRACT_MANAGER
from web3.utils.filters import Filter

from raiden.network.proxies import Token
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.transactions import (
    check_transaction_threw,
)
from raiden.exceptions import (
    DuplicatedChannelError,
    ChannelIncorrectStateError,
    SamePeerAddress,
    TransactionThrew,
    InvalidAddress,
    ContractVersionMismatch,
    InvalidSettleTimeout,
    DepositMismatch,
)
from raiden.settings import (
    EXPECTED_CONTRACTS_VERSION,
)
from raiden.utils import (
    compare_versions,
    pex,
    privatekey_to_address,
    typing,
)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class TokenNetwork:
    def __init__(
            self,
            jsonrpc_client,
            manager_address,
    ):
        if not is_binary_address(manager_address):
            raise InvalidAddress('Expected binary address format for token nework')

        check_address_has_code(jsonrpc_client, manager_address, CONTRACT_TOKEN_NETWORK)

        proxy = jsonrpc_client.new_contract_proxy(
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK),
            to_normalized_address(manager_address),
        )

        is_good_version = compare_versions(
            proxy.contract.functions.contract_version().call(),
            EXPECTED_CONTRACTS_VERSION,
        )
        if not is_good_version:
            raise ContractVersionMismatch('Incompatible ABI for TokenNetwork')

        self.address = manager_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.node_address = privatekey_to_address(self.client.privkey)
        self.open_channel_transactions = dict()

        # Forbids concurrent operations on the same channel
        self.channel_operations_lock = defaultdict(RLock)

        # Serializes concurent deposits on this token network. This must be an
        # exclusive lock, since we need to coordinate the approve and
        # setTotalDeposit calls.
        self.deposit_lock = Semaphore()

    def _call_and_check_result(self, function_name: str, *args):
        fn = getattr(self.proxy.contract.functions, function_name)
        call_result = fn(*args).call()

        if call_result == b'':
            raise RuntimeError(f"Call to '{function_name}' returned nothing")

        return call_result

    def token_address(self) -> typing.Address:
        """ Return the token of this manager. """
        return to_canonical_address(self.proxy.contract.functions.token().call())

    def new_netting_channel(
            self,
            partner: typing.Address,
            settle_timeout: int,
    ) -> typing.ChannelID:
        """ Creates a new channel in the TokenNetwork contract.

        Args:
            partner: The peer to open the channel with.
            settle_timeout: The settle timout to use for this channel.

        Returns:
            The address of the new netting channel.
        """
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

        # Prevent concurrent attempts to open a channel with the same token and
        # partner address.
        if partner not in self.open_channel_transactions:
            new_open_channel_transaction = AsyncResult()
            self.open_channel_transactions[partner] = new_open_channel_transaction

            try:
                transaction_hash = self._new_netting_channel(partner, settle_timeout)
            except Exception as e:
                new_open_channel_transaction.set_exception(e)
                raise
            else:
                new_open_channel_transaction.set(transaction_hash)
            finally:
                self.open_channel_transactions.pop(partner, None)
        else:
            # All other concurrent threads should block on the result of opening this channel
            self.open_channel_transactions[partner].get()

        channel_created = self.channel_exists(self.node_address, partner)
        if channel_created is False:
            log.error(
                'creating new channel failed',
                peer1=pex(self.node_address),
                peer2=pex(partner),
            )
            raise RuntimeError('creating new channel failed')

        channel_identifier = self.detail_channel(self.node_address, partner)['channel_identifier']

        log.info(
            'new_netting_channel called',
            peer1=pex(self.node_address),
            peer2=pex(partner),
            channel_identifier=encode_hex(channel_identifier),
        )

        return channel_identifier

    def _new_netting_channel(self, partner: typing.Address, settle_timeout: int):
        if self.channel_exists(self.node_address, partner):
            raise DuplicatedChannelError('Channel with given partner address already exists')

        transaction_hash = self.proxy.transact(
            'openChannel',
            self.node_address,
            partner,
            settle_timeout,
        )

        if not transaction_hash:
            raise RuntimeError('open channel transaction failed')

        self.client.poll(transaction_hash)

        if check_transaction_threw(self.client, transaction_hash):
            raise DuplicatedChannelError('Duplicated channel')

        return transaction_hash

    def channel_exists(self, participant1: typing.Address, participant2: typing.Address) -> bool:
        channel_data = self.detail_channel(participant1, participant2)

        if not isinstance(channel_data['state'], typing.T_ChannelState):
            raise ValueError('channel state must be of type ChannelState')

        log.debug('channel data {}'.format(channel_data))

        return channel_data['state'] > CHANNEL_STATE_NONEXISTENT

    def detail_participant(
            self,
            participant1: typing.Address,
            participant2: typing.Address,
    ) -> Dict:
        """ Returns a dictionary with the channel participant information. """
        data = self._call_and_check_result(
            'getChannelParticipantInfo',
            to_checksum_address(participant1),
            to_checksum_address(participant2),
        )
        return {
            'deposit': data[0],
            'withdrawn': data[1],
            'is_closer': data[2],
            'balance_hash': data[3],
            'nonce': data[4],
        }

    def detail_channel(self, participant1: typing.Address, participant2: typing.Address) -> Dict:
        """ Returns a dictionary with the channel specific information. """
        channel_data = self._call_and_check_result(
            'getChannelInfo',
            to_checksum_address(participant1),
            to_checksum_address(participant2),
        )

        assert isinstance(channel_data[0], typing.T_ChannelID)

        return {
            'channel_identifier': channel_data[0],
            'settle_block_number': channel_data[1],
            'state': channel_data[2],
        }

    def detail_participants(
            self,
            participant1: typing.Address,
            participant2: typing.Address,
    ) -> Dict:
        """ Returns a dictionary with the participants' channel information.

        Note:
            For now one of the participants has to be the node_address
        """
        if self.node_address not in (participant1, participant2):
            raise ValueError('One participant must be the node address')

        if self.node_address == participant2:
            participant1, participant2 = participant2, participant1

        our_data = self.detail_participant(participant1, participant2)
        partner_data = self.detail_participant(participant2, participant1)
        return {
            'our_address': participant1,
            'our_deposit': our_data['deposit'],
            'our_withdrawn': our_data['withdrawn'],
            'our_is_closer': our_data['is_closer'],
            'our_balance_hash': our_data['balance_hash'],
            'our_nonce': our_data['nonce'],
            'partner_address': participant2,
            'partner_deposit': partner_data['deposit'],
            'partner_withdrawn': partner_data['withdrawn'],
            'partner_is_closer': partner_data['is_closer'],
            'partner_balance_hash': partner_data['balance_hash'],
            'partner_nonce': partner_data['nonce'],
        }

    def detail(self, participant1: typing.Address, participant2: typing.Address) -> Dict:
        """ Returns a dictionary with all the details of the channel and the channel participants.

        Note:
            For now one of the participants has to be the node_address
        """
        if self.node_address not in (participant1, participant2):
            raise ValueError('One participant must be the node address')

        if self.node_address == participant2:
            participant1, participant2 = participant2, participant1

        channel_data = self.detail_channel(participant1, participant2)
        participants_data = self.detail_participants(participant1, participant2)
        chain_id = self.proxy.contract.functions.chain_id().call()

        return {
            'chain_id': chain_id,
            **channel_data,
            **participants_data,
        }

    def settlement_timeout_min(self) -> int:
        """ Returns the minimal settlement timeout for the token network. """
        return self.proxy.contract.functions.settlement_timeout_min().call()

    def settlement_timeout_max(self) -> int:
        """ Returns the maximal settlement timeout for the token network. """
        return self.proxy.contract.functions.settlement_timeout_max().call()

    def locked_amount_by_locksroot(
            self,
            participant1: typing.Address,
            participant2: typing.Address,
            locksroot: typing.Locksroot,
    ) -> int:
        """ Returns the locked amount for a specific participant's locksroot. """
        data = self._call_and_check_result(
            'getParticipantLockedAmount',
            to_checksum_address(participant1),
            to_checksum_address(participant2),
            locksroot,
        )
        return data

    def settle_block_number(
            self,
            participant1: typing.Address,
            participant2: typing.Address,
    ) -> typing.BlockNumber:
        """ Returns the channel settle_block_number. """
        channel_data = self.detail_channel(participant1, participant2)
        return channel_data.get('settle_block_number')

    def channel_is_opened(
            self,
            participant1: typing.Address,
            participant2: typing.Address,
    ) -> bool:
        """ Returns true if the channel is in an open state, false otherwise. """
        channel_data = self.detail_channel(participant1, participant2)

        if not isinstance(channel_data['state'], typing.T_ChannelState):
            raise ValueError('channel state must be of type ChannelState')

        return channel_data.get('state') == CHANNEL_STATE_OPENED

    def channel_is_closed(
            self,
            participant1: typing.Address,
            participant2: typing.Address,
    ) -> bool:
        """ Returns true if the channel is in a closed state, false otherwise. """
        channel_data = self.detail_channel(participant1, participant2)

        if not isinstance(channel_data['state'], typing.T_ChannelState):
            raise ValueError('channel state must be of type ChannelState')

        return channel_data.get('state') == CHANNEL_STATE_CLOSED

    def channel_is_settled(
            self,
            participant1: typing.Address,
            participant2: typing.Address,
    ) -> bool:
        """ Returns true if the channel is in a settled state, false otherwise. """
        channel_data = self.detail_channel(participant1, participant2)

        if not isinstance(channel_data['state'], typing.T_ChannelState):
            raise ValueError('channel state must be of type ChannelState')

        return channel_data.get('state') == CHANNEL_STATE_SETTLED

    def closing_address(
            self,
            participant1: typing.Address,
            participant2: typing.Address,
    ) -> Optional[typing.Address]:
        """ Returns the address of the closer, if the channel is closed, None
        otherwise. """
        participants_data = self.detail_participants(participant1, participant2)

        if participants_data.get('our_is_closer'):
            return participants_data.get('our_address')
        elif participants_data.get('partner_is_closer'):
            return participants_data.get('partner_address')

        return None

    def can_transfer(
            self,
            participant1: typing.Address,
            participant2: typing.Address,
    ) -> bool:
        """ Returns True if the channel is opened and the node has deposit in
        it.

        Note: Having a deposit does not imply having a balance for off-chain
        transfers. """
        opened = self.channel_is_opened(participant1, participant2)

        if opened is False:
            return False

        return self.detail_participant(participant1, participant2)['deposit'] > 0

    def set_total_deposit(self, total_deposit: typing.TokenAmount, partner: typing.Address):
        """ Set total token deposit in the channel to total_deposit.

        Raises:
            ChannelBusyError: If the channel is busy with another operation
            RuntimeError: If the token address is empty.
        """
        if not isinstance(total_deposit, int):
            raise ValueError('total_deposit needs to be an integral number.')

        token_address = self.token_address()
        token = Token(self.client, token_address)

        with self.channel_operations_lock[partner], self.deposit_lock:
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
            current_deposit = self.detail_participant(self.node_address, partner)['deposit']
            amount_to_deposit = total_deposit - current_deposit
            if total_deposit < current_deposit:
                raise DepositMismatch(
                    f'Current deposit ({current_deposit}) is already larger '
                    f'than the requested total deposit amount ({total_deposit})',
                )
            if amount_to_deposit <= 0:
                raise ValueError(f'deposit {amount_to_deposit} must be greater than 0.')

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
                raise ValueError(
                    f'deposit {amount_to_deposit} can not be larger than the '
                    f'available balance {current_balance}, '
                    f'for token at address {pex(token_address)}',
                )

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
            token.approve(self.address, amount_to_deposit)

            log_details = {
                'token_network': pex(self.address),
                'node': pex(self.node_address),
                'partner': pex(partner),
                'total_deposit': total_deposit,
                'amount_to_deposit': amount_to_deposit,
                'id': id(self),
            }
            log.info('deposit called', **log_details)

            transaction_hash = self.proxy.transact(
                'setTotalDeposit',
                self.node_address,
                total_deposit,
                partner,
            )
            self.client.poll(transaction_hash)

            receipt_or_none = check_transaction_threw(self.client, transaction_hash)

            if receipt_or_none:
                if token.allowance(self.node_address, self.address) < amount_to_deposit:
                    log_msg = (
                        'deposit failed. The allowance is insufficient, check concurrent deposits '
                        'for the same token network but different proxies.'
                    )
                elif token.balance_of(self.node_address) < amount_to_deposit:
                    log_msg = 'deposit failed. The address doesnt have funds'
                else:
                    log_msg = 'deposit failed'

                log.critical(log_msg, **log_details)

                channel_opened = self.channel_is_opened(self.node_address, partner)
                if channel_opened is False:
                    raise ChannelIncorrectStateError(
                        'Channel is not in an opened state. A deposit cannot be made',
                    )
                raise TransactionThrew('Deposit', receipt_or_none)

            log.info('deposit successful', **log_details)

    def close(
            self,
            partner: typing.Address,
            nonce: typing.Nonce,
            balance_hash: typing.BalanceHash,
            additional_hash: typing.AdditionalHash,
            signature: typing.Signature,
    ):
        """ Close the channel using the provided balance proof.

        Raises:
            ChannelBusyError: If the channel is busy with another operation.
            ChannelIncorrectStateError: If the channel is not in the open state.
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
        log.info('close called', **log_details)

        if not self.channel_is_opened(self.node_address, partner):
            raise ChannelIncorrectStateError(
                'Channel is not in an opened state. It cannot be closed.',
            )

        with self.channel_operations_lock[partner]:
            transaction_hash = self.proxy.transact(
                'closeChannel',
                partner,
                balance_hash,
                nonce,
                additional_hash,
                signature,
            )
            self.client.poll(transaction_hash)

            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            if receipt_or_none:
                log.critical('close failed', **log_details)
                if not self.channel_is_opened(self.node_address, partner):
                    raise ChannelIncorrectStateError(
                        'Channel is not in an opened state. It cannot be closed.',
                    )
                raise TransactionThrew('Close', receipt_or_none)

            log.info('close successful', **log_details)

    def update_transfer(
            self,
            partner: typing.Address,
            nonce: typing.Nonce,
            balance_hash: typing.BalanceHash,
            additional_hash: typing.AdditionalHash,
            closing_signature: typing.Signature,
            non_closing_signature: typing.Signature,
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
        log.info('updateNonClosingBalanceProof called', **log_details)

        transaction_hash = self.proxy.transact(
            'updateNonClosingBalanceProof',
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
        if receipt_or_none:
            log.critical('updateNonClosingBalanceProof failed', **log_details)
            channel_closed = self.channel_is_closed(self.node_address, partner)
            if channel_closed is False:
                raise ChannelIncorrectStateError('Channel is not in a closed state')
            raise TransactionThrew('Update NonClosing balance proof', receipt_or_none)

        log.info('updateNonClosingBalanceProof successful', **log_details)

    def withdraw(
            self,
            partner: typing.Address,
            total_withdraw: int,
            partner_signature: typing.Address,
            signature: typing.Signature,
    ):
        log_details = {
            'token_network': pex(self.address),
            'node': pex(self.node_address),
            'partner': pex(partner),
            'total_withdraw': total_withdraw,
            'partner_signature': encode_hex(partner_signature),
            'signature': encode_hex(signature),
        }
        log.info('withdraw called', **log_details)

        with self.channel_operations_lock[partner]:
            transaction_hash = self.proxy.transact(
                'setTotalWithdraw',
                self.node_address,
                partner,
                total_withdraw,
                partner_signature,
                signature,
            )
            self.client.poll(transaction_hash)

            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            if receipt_or_none:
                log.critical('withdraw failed', **log_details)
                channel_opened = self.channel_is_opened(self.node_address, partner)
                if channel_opened is False:
                    raise ChannelIncorrectStateError(
                        'Channel is not in an opened state. A withdraw cannot be made',
                    )
                raise TransactionThrew('Withdraw', receipt_or_none)

            log.info('withdraw successful', **log_details)

    def unlock(self, partner: typing.Address, merkle_tree_leaves: typing.MerkleTreeLeaves):
        log_details = {
            'token_network': pex(self.address),
            'node': pex(self.node_address),
            'partner': pex(partner),
            'merkle_tree_leaves': merkle_tree_leaves,
        }

        if merkle_tree_leaves is None or not merkle_tree_leaves:
            log.info('skipping unlock, tree is empty', **log_details)
            return

        log.info('unlock called', **log_details)
        leaves_packed = b''.join(lock.encoded for lock in merkle_tree_leaves)

        transaction_hash = self.proxy.transact(
            'unlock',
            self.node_address,
            partner,
            leaves_packed,
        )

        self.client.poll(transaction_hash)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)

        if receipt_or_none:
            channel_settled = self.channel_is_settled(self.node_address, partner)

            if channel_settled is False:
                log.critical('unlock failed. Channel is not in a settled state', **log_details)
                raise ChannelIncorrectStateError(
                    'Channel is not in a settled state. An unlock cannot be made',
                )

            log.critical('unlock failed', **log_details)
            raise TransactionThrew('Unlock', receipt_or_none)

        log.info('unlock successful', **log_details)

    def settle(
            self,
            transferred_amount: int,
            locked_amount: int,
            locksroot: typing.Locksroot,
            partner: typing.Address,
            partner_transferred_amount: int,
            partner_locked_amount: int,
            partner_locksroot: typing.Locksroot,
    ):
        """ Settle the channel.

        Raises:
            ChannelBusyError: If the channel is busy with another operation
        """
        log_details = {
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
        log.info('settle called', **log_details)

        with self.channel_operations_lock[partner]:
            our_maximum = transferred_amount + locked_amount
            partner_maximum = partner_transferred_amount + partner_locked_amount

            # The second participant transferred + locked amount must be higher
            our_bp_is_larger = our_maximum > partner_maximum

            if our_bp_is_larger:
                transaction_hash = self.proxy.transact(
                    'settleChannel',
                    partner,
                    partner_transferred_amount,
                    partner_locked_amount,
                    partner_locksroot,
                    self.node_address,
                    transferred_amount,
                    locked_amount,
                    locksroot,
                )
            else:
                transaction_hash = self.proxy.transact(
                    'settleChannel',
                    self.node_address,
                    transferred_amount,
                    locked_amount,
                    locksroot,
                    partner,
                    partner_transferred_amount,
                    partner_locked_amount,
                    partner_locksroot,
                )

            self.client.poll(transaction_hash)
            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            if receipt_or_none:
                channel_exists = self.channel_exists(self.node_address, partner)

                if not channel_exists:
                    log.info('settle failed, channel already settled', **log_details)
                    raise ChannelIncorrectStateError(
                        'Channel already settled or non-existent',
                    )

                channel_closed = self.channel_is_closed(self.node_address, partner)
                if channel_closed is False:
                    log.info('settle failed, channel is not closed', **log_details)
                    raise ChannelIncorrectStateError(
                        'Channel is not in a closed state. It cannot be settled',
                    )

                log.info('settle failed', **log_details)
                raise TransactionThrew('Settle', receipt_or_none)

            log.info('settle successful', **log_details)

    def events_filter(
            self,
            topics: List[str] = None,
            from_block: typing.BlockSpecification = None,
            to_block: typing.BlockSpecification = None,
    ) -> Filter:
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

    def channelnew_filter(
            self,
            from_block: typing.BlockSpecification = 0,
            to_block: typing.BlockSpecification = 'latest',
    ) -> Filter:
        """ Install a new filter for ChannelNew events.

        Args:
            from_block: Create filter starting from this block number (default: 0).
            to_block: Create filter stopping at this block number (default: 'latest').

        Return:
            The filter instance.
        """
        event_abi = CONTRACT_MANAGER.get_event_abi(CONTRACT_TOKEN_NETWORK, EVENT_CHANNEL_OPENED)
        event_id = encode_hex(event_abi_to_log_topic(event_abi))
        topics = [event_id]
        return self.events_filter(topics, from_block, to_block)

    def all_events_filter(
            self,
            from_block: typing.BlockSpecification = 0,
            to_block: typing.BlockSpecification = 'latest',
    ) -> Filter:
        """ Install a new filter for all the events emitted by the current token network contract

        Args:
            from_block: Create filter starting from this block number (default: 0).
            to_block: Create filter stopping at this block number (default: 'latest').

        Return:
            The filter instance.
        """
        return self.events_filter(None, from_block, to_block)
