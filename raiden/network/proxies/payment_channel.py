# -*- coding: utf-8 -*-
from typing import Dict

from web3.utils.filters import Filter
from raiden.utils import typing
from raiden.utils.filters import get_filter_args_for_channel_from_token_network

from raiden.network.proxies import TokenNetwork


class PaymentChannel:
    def __init__(
        self,
        token_network: TokenNetwork,
        partner_address: typing.Address,
    ):
        self.token_network = token_network
        self.partner_address = partner_address

    def token_address(self) -> typing.Address:
        """ Returns the address of the token for the channel. """
        return self.token_network.token_address()

    def channel_identifier(self) -> typing.ChannelID:
        """ Returns the channel identifier. """
        return self.token_network.detail_channel(self.partner_address)['channel_identifier']

    def detail(self) -> Dict:
        """ Returns the channel details. """
        return self.token_network.detail(self.partner_address)

    def settle_block_number(self) -> int:
        """ Returns the channels settle block number.

        This is relative while the channel is open and becomes absolute when the channel is closed
        """
        return self.token_network.settle_block_number(self.partner_address)

    def settle_timeout(self) -> int:
        """ Returns the channels settle_timeout. """

        # There is no way to get the settle timeout after the channel has been closed as
        # we're saving gas. Therefore get the ChannelOpened event and get the timeout there.
        filter = self.token_network.proxy.contract.events.ChannelOpened.createFilter(
            fromBlock=0,
            argument_filters={
                'channel_identifier': self.channel_identifier(),
            },
        )

        events = filter.get_all_entries()
        # uninstall the filter, otherwise it leaks
        self.token_network.proxy.contract.web3.eth.uninstallFilter(filter.filter_id)

        assert len(events) > 0, 'No matching ChannelOpen event found.'

        # we want the latest event here, there might have been multiple channels
        return events[-1]['args']['settle_timeout']

    def opened(self) -> bool:
        """ Returns if the channel is opened. """
        return self.token_network.channel_is_opened(self.partner_address)

    def closed(self) -> bool:
        """ Returns if the channel is closed. """
        return self.token_network.channel_is_closed(self.partner_address)

    def settled(self) -> bool:
        """ Returns if the channel is settled. """
        return self.token_network.channel_is_settled(self.partner_address)

    def closing_address(self) -> typing.Address:
        """ Returns the address of the closer of the channel. """
        return self.token_network.closing_address(self.partner_address)

    def can_transfer(self) -> bool:
        """ Returns True if the channel is opened and the node has deposit in it. """
        return self.token_network.can_transfer(self.partner_address)

    def deposit(self, total_deposit: typing.TokenAmount):
        self.token_network.deposit(total_deposit, self.partner_address)

    def close(
            self,
            nonce: typing.Nonce,
            balance_hash: typing.BalanceHash,
            additional_hash: typing.AdditionalHash,
            signature: typing.Signature,
    ):
        """ Closes the channel using the provided balance proof. """
        self.token_network.close(
            partner=self.partner_address,
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
            partner=self.partner_address,
            nonce=nonce,
            balance_hash=balance_hash,
            additional_hash=additional_hash,
            partner_signature=partner_signature,
            signature=signature,
        )

    def unlock(self, merkle_tree_leaves: bytes):
        self.token_network.unlock(
            self.partner_address,
            merkle_tree_leaves,
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
        """ Settles the channel. """
        self.token_network.settle(
            transferred_amount=transferred_amount,
            locked_amount=locked_amount,
            locksroot=locksroot,
            partner=self.partner_address,
            partner_transferred_amount=partner_transferred_amount,
            partner_locked_amount=partner_locked_amount,
            partner_locksroot=partner_locksroot,
        )

    def all_events_filter(
            self,
            from_block: typing.BlockSpecification = None,
            to_block: typing.BlockSpecification = None,
    ) -> Filter:
        args = get_filter_args_for_channel_from_token_network(
            token_network_address=self.token_network.address,
            channel_identifier=self.channel_identifier(),
            from_block=from_block,
            to_block=to_block,
        )

        return self.token_network.client.new_filter(
            contract_address=args['address'],
            topics=args['topics'],
            from_block=args['fromBlock'],
            to_block=args['toBlock'],
        )
