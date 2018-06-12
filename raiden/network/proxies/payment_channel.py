# -*- coding: utf-8 -*-
from typing import Dict

from raiden.network.proxies import TokenNetwork
from raiden.utils import typing


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

    def settle_block_number(self) -> typing.BlockNumber:
        """ Returns the settle block of the channel"""
        return self.token_network.settle_block_number(self.partner_address)

    def openend(self) -> bool:
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

    def events_filter(self):
        raise NotImplementedError('PaymentChannel.events_filter not implemented')

    def all_events_filter(self):
        raise NotImplementedError('PaymentChannel.all_events_filter not implemented')
