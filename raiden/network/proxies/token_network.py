# -*- coding: utf-8 -*-
from binascii import unhexlify
from gevent.lock import RLock
from gevent.event import AsyncResult
from typing import List, Union, Optional
from raiden.utils import typing

import structlog

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_TOKEN_NETWORK,
    EVENT_CHANNEL_NEW2,
    CHANNEL_STATE_NONEXISTENT,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLED,
)
from raiden.constants import (
    NETTINGCHANNEL_SETTLE_TIMEOUT_MIN,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MAX,
)
from raiden.network.rpc.filters import (
    new_filter,
    Filter,
)
from raiden.network.rpc.client import check_address_has_code
from raiden.network.proxies.token import Token
from raiden.network.rpc.transactions import (
    check_transaction_threw,
    estimate_and_transact,
)
from raiden.exceptions import (
    DuplicatedChannelError,
    ChannelIncorrectStateError,
    InvalidSettleTimeout,
    SamePeerAddress,
    ChannelBusyError,
    TransactionThrew,
    InvalidAddress,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
)
from raiden.utils import (
    address_decoder,
    address_encoder,
    encode_hex,
    isaddress,
    pex,
    privatekey_to_address,
    releasing,
)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class TokenNetwork:
    def __init__(
            self,
            jsonrpc_client,
            manager_address,
            poll_timeout=DEFAULT_POLL_TIMEOUT,
    ):
        # pylint: disable=too-many-arguments

        if not isaddress(manager_address):
            raise InvalidAddress('Expected binary address format for token nework')

        check_address_has_code(jsonrpc_client, manager_address, 'Channel Manager')

        proxy = jsonrpc_client.new_contract_proxy(
            CONTRACT_MANAGER.get_abi(CONTRACT_TOKEN_NETWORK),
            address_encoder(manager_address),
        )

        CONTRACT_MANAGER.check_contract_version(
            proxy.call('contract_version').decode(),
            CONTRACT_TOKEN_NETWORK
        )

        self.address = manager_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.node_address = privatekey_to_address(self.client.privkey)
        self.poll_timeout = poll_timeout
        # Prevents concurrent deposit, withdraw, close, or settle operations on the same channel
        self.channel_operations_lock = dict()
        self.open_channel_transactions = dict()

    def _call_and_check_result(self, function_name: str, *args):
        call_result = self.proxy.call(function_name, *args)

        if call_result == b'':
            raise RuntimeError(
                "Call to '{}' returned nothing".format(function_name)
            )

        return call_result

    def _check_channel_lock(self, partner: typing.Address):
        if partner not in self.channel_operations_lock:
            self.channel_operations_lock[partner] = RLock()

        if not self.channel_operations_lock[partner].acquire(blocking=False):
            raise ChannelBusyError(
                f'Channel between {self.node_address} and {partner} is '
                f'busy with another ongoing operation.'
            )

    def token_address(self) -> typing.Address:
        """ Return the token of this manager. """
        return address_decoder(self.proxy.call('token'))

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
        if not isaddress(partner):
            raise InvalidAddress('Expected binary address format for channel partner')

        invalid_timeout = (
            settle_timeout < NETTINGCHANNEL_SETTLE_TIMEOUT_MIN or
            settle_timeout > NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
        )
        if invalid_timeout:
            raise InvalidSettleTimeout('settle_timeout must be in range [{}, {}]'.format(
                NETTINGCHANNEL_SETTLE_TIMEOUT_MIN, NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
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
            transaction_hash = self.open_channel_transactions[partner].get()

        channel_created = self.channel_exists(partner)
        if channel_created is False:
            log.error(
                'creating new channel failed',
                peer1=pex(self.node_address),
                peer2=pex(partner)
            )
            raise RuntimeError('creating new channel failed')

        channel_identifier = self.detail_channel(partner)['channel_identifier']

        log.info(
            'new_netting_channel called',
            peer1=pex(self.node_address),
            peer2=pex(partner),
            channel_identifier=channel_identifier,
        )

        return channel_identifier

    def _new_netting_channel(self, partner: typing.Address, settle_timeout: int):
        if self.channel_exists(partner):
            raise DuplicatedChannelError('Channel with given partner address already exists')

        transaction_hash = estimate_and_transact(
            self.proxy,
            'openChannel',
            self.node_address,
            partner,
            settle_timeout,
        )

        if not transaction_hash:
            raise RuntimeError('open channel transaction failed')

        self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)

        if check_transaction_threw(self.client, transaction_hash):
            raise DuplicatedChannelError('Duplicated channel')

        return transaction_hash

    def channel_exists(self, partner: typing.Address) -> bool:
        channel_data = self.detail_channel(partner)

        if not isinstance(channel_data['state'], typing.T_ChannelState):
            raise ValueError('channel state must be of type ChannelState')

        log.debug('channel data {}'.format(channel_data))

        return channel_data['state'] > CHANNEL_STATE_NONEXISTENT

    def detail_participant(self, participant: typing.Address, partner: typing.Address):
        """ Returns a dictionary with the channel participant information. """
        data = self._call_and_check_result('getChannelParticipantInfo', participant, partner)
        return {
            'deposit': data[0],
            'withdrawn': data[1],
            'is_closer': data[2],
            'balance_hash': data[3],
            'nonce': data[4],
        }

    def detail_channel(self, partner: typing.Address):
        """ Returns a dictionary with the channel specific information. """
        channel_data = self._call_and_check_result('getChannelInfo', self.node_address, partner)

        assert isinstance(channel_data[0], typing.T_ChannelID)

        return {
            'channel_identifier': channel_data[0],
            'settle_block_number': channel_data[1],
            'state': channel_data[2],
        }

    def detail_participants(self, partner: typing.Address):
        """ Returns a dictionary with the participants' channel information. """
        our_data = self.detail_participant(self.node_address, partner)
        partner_data = self.detail_participant(partner, self.node_address)
        return {
            'our_address': self.node_address,
            'our_balance': our_data['deposit'],
            'our_withdrawn': our_data['withdrawn'],
            'our_is_closer': our_data['is_closer'],
            'our_balance_hash': our_data['balance_hash'],
            'our_nonce': our_data['nonce'],
            'partner_address': partner,
            'partner_balance': partner_data['deposit'],
            'partner_withdrawn': partner_data['withdrawn'],
            'partner_is_closer': partner_data['is_closer'],
            'partner_balance_hash': partner_data['balance_hash'],
            'partner_nonce': partner_data['nonce'],
        }

    def detail(self, partner: typing.Address):
        """ Returns a dictionary with all the details of the channel and the channel participants.
        """
        channel_data = self.detail_channel(partner)
        participants_data = self.detail_participants(partner)

        return {
            **channel_data,
            **participants_data,
        }

    def locked_amount_by_locksroot(
            self,
            participant: typing.Address,
            partner: typing.Address,
            locksroot: typing.Locksroot,
    ) -> int:
        """ Returns the locked amount for a specific participant's locksroot. """
        data = self._call_and_check_result(
            'getParticipantLockedAmount',
            participant,
            partner,
            locksroot
        )
        return data

    def settle_block_number(self, partner: typing.Address):
        """ Returns the channel settle_block_number. """
        channel_data = self.detail_channel(partner)
        return channel_data.get('settle_block_number')

    def channel_is_opened(self, partner: typing.Address) -> bool:
        """ Returns true if the channel is in an open state, false otherwise. """
        channel_data = self.detail_channel(partner)

        if not isinstance(channel_data['state'], typing.T_ChannelState):
            raise ValueError('channel state must be of type ChannelState')

        return channel_data.get('state') == CHANNEL_STATE_OPENED

    def channel_is_closed(self, partner: typing.Address) -> bool:
        """ Returns true if the channel is in a closed state, false otherwise. """
        channel_data = self.detail_channel(partner)

        if not isinstance(channel_data['state'], typing.T_ChannelState):
            raise ValueError('channel state must be of type ChannelState')

        return channel_data.get('state') == CHANNEL_STATE_CLOSED

    def channel_is_settled(self, partner: typing.Address) -> bool:
        """ Returns true if the channel is in a settled state, false otherwise. """
        channel_data = self.detail_channel(partner)

        if not isinstance(channel_data['state'], typing.T_ChannelState):
            raise ValueError('channel state must be of type ChannelState')

        return channel_data.get('state') == CHANNEL_STATE_SETTLED

    def closing_address(self, partner: typing.Address):
        """ Returns the address of the closer, if the channel is closed, None
        otherwise. """
        participants_data = self.detail_participants(partner)

        if participants_data.get('our_is_closer'):
            return participants_data.get('our_address')
        elif participants_data.get('partner_is_closer'):
            return participants_data.get('partner_address')

        return None

    def can_transfer(self, partner: typing.Address):
        """ Returns True if the channel is opened and the node has deposit in
        it.

        Note: Having a deposit does not imply having a balance for off-chain
        transfers. """
        opened = self.channel_is_opened(partner)

        if opened is False:
            return False

        return self.detail_participant(self.node_address, partner)['deposit'] > 0

    def deposit(self, total_deposit: int, partner: typing.Address):
        """ Set total token deposit in the channel to total_deposit.

        Raises:
            ChannelBusyError: If the channel is busy with another operation
            RuntimeError: If the token address is empty.
        """
        if not isinstance(total_deposit, int):
            raise ValueError('total_deposit needs to be an integral number.')

        token_address = self.token_address()

        token = Token(
            self.client,
            token_address,
            self.poll_timeout,
        )
        current_balance = token.balance_of(self.node_address)
        current_deposit = self.detail_participant(self.node_address, partner)['deposit']
        amount_to_deposit = total_deposit - current_deposit

        if amount_to_deposit <= 0:
            raise ValueError('deposit [{}] must be greater than 0.'.format(
                amount_to_deposit,
            ))

        if current_balance < amount_to_deposit:
            raise ValueError(
                f'deposit {amount_to_deposit} cant be larger than the '
                f'available balance {current_balance}, '
                f'for token at address {pex(token_address)}'
            )

        log.info(
            'deposit called',
            token_network=pex(self.address),
            node=pex(self.node_address),
            partner=pex(partner),
            total_deposit=total_deposit,
            amount_to_deposit=amount_to_deposit,
        )

        self._check_channel_lock(partner)

        with releasing(self.channel_operations_lock[partner]):
            transaction_hash = estimate_and_transact(
                self.proxy,
                'setTotalDeposit',
                self.node_address,
                total_deposit,
                partner,
            )

            self.client.poll(
                unhexlify(transaction_hash),
                timeout=self.poll_timeout,
            )

            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            if receipt_or_none:
                log.critical(
                    'deposit failed',
                    token_network=pex(self.address),
                    node=pex(self.node_address),
                    partner=pex(partner),
                    total_deposit=total_deposit,
                )

                channel_opened = self.channel_is_opened(partner)
                if channel_opened is False:
                    raise ChannelIncorrectStateError(
                        'Channel is not in an opened state. A deposit cannot be made'
                    )
                raise TransactionThrew('Deposit', receipt_or_none)

            log.info(
                'deposit successful',
                token_network=pex(self.address),
                node=pex(self.node_address),
                partner=pex(partner),
                total_deposit=total_deposit,
            )

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
        """

        log.info(
            'close called',
            token_network=pex(self.address),
            node=pex(self.node_address),
            partner=pex(partner),
            nonce=nonce,
            balance_hash=encode_hex(balance_hash),
            additional_hash=encode_hex(additional_hash),
            signature=encode_hex(signature),
        )

        self._check_channel_lock(partner)

        with releasing(self.channel_operations_lock[partner]):
            transaction_hash = estimate_and_transact(
                self.proxy,
                'closeChannel',
                partner,
                balance_hash,
                nonce,
                additional_hash,
                signature,
            )
            self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)

            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            if receipt_or_none:
                log.critical(
                    'close failed',
                    token_network=pex(self.address),
                    node=pex(self.node_address),
                    partner=pex(partner),
                    nonce=nonce,
                    balance_hash=encode_hex(balance_hash),
                    additional_hash=encode_hex(additional_hash),
                    signature=encode_hex(signature),
                )
                channel_opened = self.channel_is_opened(partner)
                if channel_opened is False:
                    raise ChannelIncorrectStateError(
                        'Channel is not in an opened state. It cannot be closed.'
                    )
                raise TransactionThrew('Close', receipt_or_none)

            log.info(
                'close successful',
                token_network=pex(self.address),
                node=pex(self.node_address),
                partner=pex(partner),
                nonce=nonce,
                balance_hash=encode_hex(balance_hash),
                additional_hash=encode_hex(additional_hash),
                signature=encode_hex(signature),
            )

    def update_transfer(
            self,
            partner: typing.Address,
            nonce: typing.Nonce,
            balance_hash: typing.BalanceHash,
            additional_hash: typing.AdditionalHash,
            partner_signature: typing.Signature,
            signature: typing.Signature,
    ):
        log.info(
            'updateNonClosingBalanceProof called',
            token_network=pex(self.address),
            node=pex(self.node_address),
            partner=pex(partner),
            nonce=nonce,
            balance_hash=encode_hex(balance_hash),
            additional_hash=encode_hex(additional_hash),
            partner_signature=encode_hex(partner_signature),
            signature=encode_hex(signature),
        )

        transaction_hash = estimate_and_transact(
            self.proxy,
            'updateNonClosingBalanceProof',
            partner,
            self.node_address,
            balance_hash,
            nonce,
            additional_hash,
            partner_signature,
            signature,
        )

        self.client.poll(
            unhexlify(transaction_hash),
            timeout=self.poll_timeout,
        )

        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            log.critical(
                'updateNonClosingBalanceProof failed',
                token_network=pex(self.address),
                node=pex(self.node_address),
                partner=pex(partner),
                nonce=nonce,
                balance_hash=encode_hex(balance_hash),
                additional_hash=encode_hex(additional_hash),
                partner_signature=encode_hex(partner_signature),
                signature=encode_hex(signature),
            )
            channel_closed = self.channel_is_closed(partner)
            if channel_closed is False:
                raise ChannelIncorrectStateError('Channel is not in a closed state')
            raise TransactionThrew('Update NonClosing balance proof', receipt_or_none)

        log.info(
            'updateNonClosingBalanceProof successful',
            token_network=pex(self.address),
            node=pex(self.node_address),
            partner=pex(partner),
            nonce=nonce,
            balance_hash=encode_hex(balance_hash),
            additional_hash=encode_hex(additional_hash),
            partner_signature=encode_hex(partner_signature),
            signature=encode_hex(signature),
        )

    def withdraw(
            self,
            partner: typing.Address,
            total_withdraw: int,
            partner_signature: typing.Address,
            signature: typing.Signature,
    ):
        log.info(
            'withdraw called',
            token_network=pex(self.address),
            node=pex(self.node_address),
            partner=pex(partner),
            total_withdraw=total_withdraw,
        )

        self._check_channel_lock(partner)

        with releasing(self.channel_operations_lock[partner]):
            transaction_hash = estimate_and_transact(
                self.proxy,
                'setTotalWithdraw',
                self.node_address,
                partner,
                total_withdraw,
                partner_signature,
                signature,
            )
            self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)

            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            if receipt_or_none:
                log.critical(
                    'withdraw failed',
                    token_network=pex(self.address),
                    node=pex(self.node_address),
                    partner=pex(partner),
                    total_withdraw=total_withdraw,
                    partner_signature=encode_hex(partner_signature),
                    signature=encode_hex(signature),
                )
                channel_opened = self.channel_is_opened(partner)
                if channel_opened is False:
                    raise ChannelIncorrectStateError(
                        'Channel is not in an opened state. A withdraw cannot be made'
                    )
                raise TransactionThrew('Withdraw', receipt_or_none)

            log.info(
                'withdraw successful',
                token_network=pex(self.address),
                node=pex(self.node_address),
                partner=pex(partner),
                total_withdraw=total_withdraw,
                partner_signature=encode_hex(partner_signature),
                signature=encode_hex(signature),
            )

    def unlock(self, partner: typing.Address, merkle_tree_leaves: bytes):
        log.info(
            'unlock called',
            token_network=pex(self.address),
            node=pex(self.node_address),
            partner=pex(partner),
        )

        # TODO see if we need to do any checks for the unlock_proof

        transaction_hash = estimate_and_transact(
            self.proxy,
            'unlock',
            self.node_address,
            partner,
            merkle_tree_leaves,
        )

        self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)

        if receipt_or_none:
            log.critical(
                'unlock failed',
                token_network=pex(self.address),
                node=pex(self.node_address),
                partner=pex(partner),
            )
            channel_settled = self.channel_is_settled(partner)
            if channel_settled is False:
                raise ChannelIncorrectStateError(
                    'Channel is not in a settled state. An unlock cannot be made'
                )
            raise TransactionThrew('Unlock', receipt_or_none)

        log.info(
            'unlock successful',
            token_network=pex(self.address),
            node=pex(self.node_address),
            partner=pex(partner),
        )

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
        log.info(
            'settle called',
            token_network=pex(self.address),
            node=pex(self.node_address),
            partner=pex(partner),
            transferred_amount=transferred_amount,
            locked_amount=locked_amount,
            locksroot=encode_hex(locksroot),
            partner_transferred_amount=partner_transferred_amount,
            partner_locked_amount=partner_locked_amount,
            partner_locksroot=encode_hex(partner_locksroot),
        )

        self._check_channel_lock(partner)

        with releasing(self.channel_operations_lock[partner]):
            transaction_hash = estimate_and_transact(
                self.proxy,
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

            self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)
            receipt_or_none = check_transaction_threw(self.client, transaction_hash)
            if receipt_or_none:
                log.info(
                    'settle failed',
                    token_network=pex(self.address),
                    node=pex(self.node_address),
                    partner=pex(partner),
                    transferred_amount=transferred_amount,
                    locked_amount=locked_amount,
                    locksroot=encode_hex(locksroot),
                    partner_transferred_amount=partner_transferred_amount,
                    partner_locked_amount=partner_locked_amount,
                    partner_locksroot=encode_hex(partner_locksroot),
                )
                channel_closed = self.channel_is_closed(partner)
                if channel_closed is False:
                    raise ChannelIncorrectStateError(
                        'Channel is not in a closed state. It cannot be settled'
                    )
                raise TransactionThrew('Settle', receipt_or_none)

            log.info(
                'settle successful',
                token_network=pex(self.address),
                node=pex(self.node_address),
                partner=pex(partner),
                transferred_amount=transferred_amount,
                locked_amount=locked_amount,
                locksroot=encode_hex(locksroot),
                partner_transferred_amount=partner_transferred_amount,
                partner_locked_amount=partner_locked_amount,
                partner_locksroot=encode_hex(partner_locksroot),
            )

    def events_filter(
            self,
            topics: Optional[List],
            from_block: Optional[int] = None,
            to_block: Optional[int] = None,
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
        filter_id_raw = new_filter(
            self.client,
            self.address,
            topics=topics,
            from_block=from_block,
            to_block=to_block
        )

        return Filter(self.client, filter_id_raw)

    def channelnew_filter(
            self,
            from_block: Union[str, int] = 0,
            to_block: Union[str, int] = 'latest',
    ) -> Filter:
        """ Install a new filter for ChannelNew events.

        Args:
            start_block:Create filter starting from this block number (default: 0).
            end_block: Create filter stopping at this block number (default: 'latest').

        Return:
            The filter instance.
        """
        topics = [CONTRACT_MANAGER.get_event_id(EVENT_CHANNEL_NEW2)]
        return self.events_filter(topics, from_block, to_block)

    def all_events_filter(self, from_block=None, to_block=None):
        """ Install a new filter for all the events emitted by the current token network contract

        Return:
            Filter: The filter instance.
        """
        return self.events_filter(None, from_block, to_block)
