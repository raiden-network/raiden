from typing import Dict

from eth_utils import decode_hex
from web3.utils.filters import Filter
from raiden.utils import typing
from raiden.utils.filters import get_filter_args_for_channel_from_token_network

from raiden.network.proxies import TokenNetwork


class PaymentChannel:
    def __init__(
        self,
        token_network: TokenNetwork,
        channel_id: typing.ChannelID,
    ):
        self.token_network = token_network
        self.channel_id = channel_id

        # query the blockchain to get the partner addresses for the channel id
        filter = token_network.proxy.contract.events.ChannelOpened.createFilter(
            fromBlock=0,
            argument_filters={
                'channel_identifier': channel_id,
            },
        )

        events = filter.get_all_entries()
        token_network.proxy.contract.web3.eth.uninstallFilter(filter.filter_id)

        if not len(events) > 0:
            raise ValueError('Channel is non-existing.')

        event = events[-1]
        self.participant = decode_hex(event['args']['participant1'])
        self.partner = decode_hex(event['args']['participant2'])

    def token_address(self) -> typing.Address:
        """ Returns the address of the token for the channel. """
        return self.token_network.token_address()

    def channel_identifier(self) -> typing.ChannelID:
        """ Returns the channel identifier. """
        return self.channel_id

    def detail(self) -> Dict:
        """ Returns the channel details. """
        return self.token_network.detail(self.participant, self.partner)

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
        return self.token_network.channel_is_opened(self.participant, self.partner)

    def closed(self) -> bool:
        """ Returns if the channel is closed. """
        return self.token_network.channel_is_closed(self.participant, self.partner)

    def settled(self) -> bool:
        """ Returns if the channel is settled. """
        return self.token_network.channel_is_settled(self.participant, self.partner)

    def closing_address(self) -> typing.Address:
        """ Returns the address of the closer of the channel. """
        return self.token_network.closing_address(self.participant, self.partner)

    def can_transfer(self) -> bool:
        """ Returns True if the channel is opened and the node has deposit in it. """
        return self.token_network.can_transfer(self.participant, self.partner)

    def deposit(self, total_deposit: typing.TokenAmount):
        self.token_network.deposit(total_deposit, self.partner)

    def close(
            self,
            nonce: typing.Nonce,
            balance_hash: typing.BalanceHash,
            additional_hash: typing.AdditionalHash,
            signature: typing.Signature,
    ):
        """ Closes the channel using the provided balance proof. """
        self.token_network.close(
            partner=self.partner,
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
            partner=self.partner,
            nonce=nonce,
            balance_hash=balance_hash,
            additional_hash=additional_hash,
            partner_signature=partner_signature,
            signature=signature,
        )

    def unlock(self, merkle_tree_leaves: bytes):
        self.token_network.unlock(
            self.partner,
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
            partner=self.partner,
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
