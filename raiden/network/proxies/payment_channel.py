from contextlib import contextmanager
from typing import Dict

from eth_abi import encode_single
from eth_utils import encode_hex, decode_hex, event_abi_to_log_topic
from gevent.lock import RLock
from raiden_contracts.constants import (
    CONTRACT_TOKEN_NETWORK,
    EVENT_CHANNEL_OPENED,
    EVENT_CHANNEL_UNLOCKED,
)
from raiden_contracts.contract_manager import CONTRACT_MANAGER
from web3.utils.filters import Filter

from raiden.utils import typing
from raiden.utils.filters import (
    get_filter_args_for_specific_event_from_channel,
    decode_event,
)
from raiden.network.proxies import TokenNetwork


class PaymentChannel:
    def __init__(
            self,
            token_network: TokenNetwork,
            channel_identifier: typing.ChannelID,
    ):
        filter_args = get_filter_args_for_specific_event_from_channel(
            token_network_address=token_network.address,
            channel_identifier=channel_identifier,
            event_name=EVENT_CHANNEL_OPENED,
        )

        events = token_network.proxy.contract.web3.eth.getLogs(filter_args)
        if not len(events) > 0:
            raise ValueError('Channel is non-existing.')

        event = decode_event(CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK), events[-1])
        participant1 = decode_hex(event['args']['participant1'])
        participant2 = decode_hex(event['args']['participant2'])

        if token_network.node_address not in (participant1, participant2):
            raise ValueError('One participant must be the node address')

        if token_network.node_address == participant2:
            participant1, participant2 = participant2, participant1

        self.channel_identifier = channel_identifier
        self.channel_operations_lock = RLock()
        self.participant1 = participant1
        self.participant2 = participant2
        self.token_network = token_network

    @contextmanager
    def lock_or_raise(self):
        with self.token_network.channel_operations_lock[self.participant2]:
            yield

    def token_address(self) -> typing.Address:
        """ Returns the address of the token for the channel. """
        return self.token_network.token_address()

    def detail(self) -> Dict:
        """ Returns the channel details. """
        return self.token_network.detail(self.participant1, self.participant2)

    def settle_timeout(self) -> int:
        """ Returns the channels settle_timeout. """

        # There is no way to get the settle timeout after the channel has been closed as
        # we're saving gas. Therefore get the ChannelOpened event and get the timeout there.
        filter_args = get_filter_args_for_specific_event_from_channel(
            token_network_address=self.token_network.address,
            channel_identifier=self.channel_identifier,
            event_name=EVENT_CHANNEL_OPENED,
        )

        events = self.token_network.proxy.contract.web3.eth.getLogs(filter_args)
        assert len(events) > 0, 'No matching ChannelOpen event found.'

        # we want the latest event here, there might have been multiple channels
        event = decode_event(CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK), events[-1])
        return event['args']['settle_timeout']

    def opened(self) -> bool:
        """ Returns if the channel is opened. """
        return self.token_network.channel_is_opened(self.participant1, self.participant2)

    def closed(self) -> bool:
        """ Returns if the channel is closed. """
        return self.token_network.channel_is_closed(self.participant1, self.participant2)

    def settled(self) -> bool:
        """ Returns if the channel is settled. """
        return self.token_network.channel_is_settled(self.participant1, self.participant2)

    def closing_address(self) -> typing.Address:
        """ Returns the address of the closer of the channel. """
        return self.token_network.closing_address(self.participant1, self.participant2)

    def can_transfer(self) -> bool:
        """ Returns True if the channel is opened and the node has deposit in it. """
        return self.token_network.can_transfer(self.participant1, self.participant2)

    def set_total_deposit(self, total_deposit: typing.TokenAmount):
        self.token_network.set_total_deposit(total_deposit, self.participant2)

    def close(
            self,
            nonce: typing.Nonce,
            balance_hash: typing.BalanceHash,
            additional_hash: typing.AdditionalHash,
            signature: typing.Signature,
    ):
        """ Closes the channel using the provided balance proof. """
        self.token_network.close(
            partner=self.participant2,
            nonce=nonce,
            balance_hash=balance_hash,
            additional_hash=additional_hash,
            signature=signature,
        )

    def update_transfer(
            self,
            nonce: typing.Nonce,
            balance_hash: typing.BalanceHash,
            additional_hash: typing.AdditionalHash,
            partner_signature: typing.Signature,
            signature: typing.Signature,
    ):
        """ Updates the channel using the provided balance proof. """
        self.token_network.update_transfer(
            partner=self.participant2,
            nonce=nonce,
            balance_hash=balance_hash,
            additional_hash=additional_hash,
            closing_signature=partner_signature,
            non_closing_signature=signature,
        )

    def unlock(self, merkle_tree_leaves: bytes):
        self.token_network.unlock(
            self.participant2,
            merkle_tree_leaves,
        )

    def settle(
            self,
            transferred_amount: int,
            locked_amount: int,
            locksroot: typing.Locksroot,
            partner_transferred_amount: int,
            partner_locked_amount: int,
            partner_locksroot: typing.Locksroot,
    ):
        """ Settles the channel. """
        self.token_network.settle(
            transferred_amount=transferred_amount,
            locked_amount=locked_amount,
            locksroot=locksroot,
            partner=self.participant2,
            partner_transferred_amount=partner_transferred_amount,
            partner_locked_amount=partner_locked_amount,
            partner_locksroot=partner_locksroot,
        )

    def all_events_filter(
            self,
            from_block: typing.BlockSpecification = None,
            to_block: typing.BlockSpecification = None,
    ) -> typing.Tuple[Filter, Filter]:

        channel_topics = [
            None,  # event topic is any
            encode_hex(encode_single('bytes32', self.channel_identifier)),  # channel_id
        ]

        # This will match the events:
        # ChannelOpened, ChannelNewDeposit, ChannelWithdraw, ChannelClosed,
        # NonClosingBalanceProofUpdated, ChannelSettled
        channel_filter = self.token_network.client.new_filter(
            contract_address=self.token_network.address,
            topics=channel_topics,
            from_block=from_block,
            to_block=to_block,
        )

        # This will match the events:
        # ChannelUnlocked
        #
        # These topics must not be joined with the channel_filter, otherwise
        # the filter ChannelSettled wont match (observed with geth
        # 1.8.11-stable-dea1ce05)

        event_unlock_abi = CONTRACT_MANAGER.get_event_abi(
            CONTRACT_TOKEN_NETWORK,
            EVENT_CHANNEL_UNLOCKED,
        )

        event_unlock_topic = encode_hex(event_abi_to_log_topic(event_unlock_abi))
        participant1_topic = encode_hex(self.participant1.rjust(32, b'\0'))
        participant2_topic = encode_hex(self.participant2.rjust(32, b'\0'))

        unlock_topics = [
            event_unlock_topic,
            [participant1_topic, participant2_topic],  # event participant1 is us or them
            [participant2_topic, participant1_topic],  # event participant2 is us or them
        ]

        unlock_filter = self.token_network.client.new_filter(
            contract_address=self.token_network.address,
            topics=unlock_topics,
            from_block=from_block,
            to_block=to_block,
        )
        return channel_filter, unlock_filter
