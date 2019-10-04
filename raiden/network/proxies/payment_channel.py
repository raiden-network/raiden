from typing import Optional

from web3.utils.filters import Filter

from raiden.blockchain.filters import decode_event, get_filter_args_for_specific_event_from_channel
from raiden.constants import UINT256_MAX
from raiden.network.proxies.token_network import ChannelDetails, TokenNetwork
from raiden.network.proxies.utils import get_channel_participants_from_open_event
from raiden.transfer.state import PendingLocksState
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    BalanceHash,
    BlockExpiration,
    BlockNumber,
    BlockSpecification,
    BlockTimeout,
    ChannelID,
    List,
    Locksroot,
    Nonce,
    Signature,
    TokenAddress,
    TokenAmount,
    WithdrawAmount,
)
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK, ChannelEvent
from raiden_contracts.contract_manager import ContractManager


class PaymentChannel:
    def __init__(
        self,
        token_network: TokenNetwork,
        channel_identifier: ChannelID,
        contract_manager: ContractManager,
    ):
        if channel_identifier <= 0 or channel_identifier > UINT256_MAX:
            raise ValueError(f"channel_identifier {channel_identifier} is not a uint256")

        participants = get_channel_participants_from_open_event(
            token_network=token_network,
            channel_identifier=channel_identifier,
            contract_manager=contract_manager,
            from_block=token_network.metadata.filters_start_at,
        )

        if not participants:
            raise ValueError("Channel is non-existing.")

        participant1, participant2 = participants

        if token_network.node_address not in (participant1, participant2):
            raise ValueError("One participant must be the node address")

        if token_network.node_address == participant2:
            participant1, participant2 = participant2, participant1

        self.channel_identifier = channel_identifier
        self.participant1 = participant1
        self.participant2 = participant2
        self.token_network = token_network
        self.client = token_network.client
        self.contract_manager = contract_manager

    def token_address(self) -> TokenAddress:
        """ Returns the address of the token for the channel. """
        return self.token_network.token_address()

    def detail(self, block_identifier: BlockSpecification) -> ChannelDetails:
        """ Returns the channel details. """
        return self.token_network.detail(
            participant1=self.participant1,
            participant2=self.participant2,
            block_identifier=block_identifier,
            channel_identifier=self.channel_identifier,
        )

    def settle_timeout(self) -> BlockTimeout:
        """ Returns the channels settle_timeout. """

        # There is no way to get the settle timeout after the channel has been closed as
        # we're saving gas. Therefore get the ChannelOpened event and get the timeout there.
        filter_args = get_filter_args_for_specific_event_from_channel(
            token_network_address=self.token_network.address,
            channel_identifier=self.channel_identifier,
            event_name=ChannelEvent.OPENED,
            contract_manager=self.contract_manager,
        )

        events = self.token_network.proxy.contract.web3.eth.getLogs(filter_args)
        assert len(events) > 0, "No matching ChannelOpen event found."

        # we want the latest event here, there might have been multiple channels
        event = decode_event(
            self.contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK), events[-1]
        )
        return event["args"]["settle_timeout"]

    def close_block_number(self) -> Optional[BlockNumber]:
        """ Returns the channel's closed block number. """

        # The closed block number is not in the smart contract storage to save
        # gas. Therefore get the ChannelClosed event is needed here.
        filter_args = get_filter_args_for_specific_event_from_channel(
            token_network_address=self.token_network.address,
            channel_identifier=self.channel_identifier,
            event_name=ChannelEvent.CLOSED,
            contract_manager=self.contract_manager,
        )

        events = self.token_network.proxy.contract.web3.eth.getLogs(filter_args)
        if not events:
            return None

        assert len(events) == 1
        event = decode_event(
            self.contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK), events[0]
        )
        return event["blockNumber"]

    def opened(self, block_identifier: BlockSpecification) -> bool:
        """ Returns if the channel is opened. """
        return self.token_network.channel_is_opened(
            participant1=self.participant1,
            participant2=self.participant2,
            block_identifier=block_identifier,
            channel_identifier=self.channel_identifier,
        )

    def closed(self, block_identifier: BlockSpecification) -> bool:
        """ Returns if the channel is closed. """
        return self.token_network.channel_is_closed(
            participant1=self.participant1,
            participant2=self.participant2,
            block_identifier=block_identifier,
            channel_identifier=self.channel_identifier,
        )

    def settled(self, block_identifier: BlockSpecification) -> bool:
        """ Returns if the channel is settled. """
        return self.token_network.channel_is_settled(
            participant1=self.participant1,
            participant2=self.participant2,
            block_identifier=block_identifier,
            channel_identifier=self.channel_identifier,
        )

    def can_transfer(self, block_identifier: BlockSpecification) -> bool:
        """ Returns True if the channel is opened and the node has deposit in it. """
        return self.token_network.can_transfer(
            participant1=self.participant1,
            participant2=self.participant2,
            block_identifier=block_identifier,
            channel_identifier=self.channel_identifier,
        )

    def set_total_deposit(
        self, total_deposit: TokenAmount, block_identifier: BlockSpecification
    ) -> None:
        self.token_network.set_total_deposit(
            given_block_identifier=block_identifier,
            channel_identifier=self.channel_identifier,
            total_deposit=total_deposit,
            partner=self.participant2,
        )

    def set_total_withdraw(
        self,
        total_withdraw: WithdrawAmount,
        participant_signature: Signature,
        partner_signature: Signature,
        expiration_block: BlockExpiration,
        block_identifier: BlockSpecification,
    ) -> None:
        self.token_network.set_total_withdraw(
            given_block_identifier=block_identifier,
            channel_identifier=self.channel_identifier,
            total_withdraw=total_withdraw,
            expiration_block=expiration_block,
            participant_signature=participant_signature,
            partner_signature=partner_signature,
            participant=self.participant1,
            partner=self.participant2,
        )

    def close(
        self,
        nonce: Nonce,
        balance_hash: BalanceHash,
        additional_hash: AdditionalHash,
        non_closing_signature: Signature,
        closing_signature: Signature,
        block_identifier: BlockSpecification,
    ) -> None:
        """ Closes the channel using the provided balance proof, and our closing signature. """
        self.token_network.close(
            channel_identifier=self.channel_identifier,
            partner=self.participant2,
            balance_hash=balance_hash,
            nonce=nonce,
            additional_hash=additional_hash,
            non_closing_signature=non_closing_signature,
            closing_signature=closing_signature,
            given_block_identifier=block_identifier,
        )

    def update_transfer(
        self,
        nonce: Nonce,
        balance_hash: BalanceHash,
        additional_hash: AdditionalHash,
        partner_signature: Signature,
        signature: Signature,
        block_identifier: BlockSpecification,
    ) -> None:
        """ Updates the channel using the provided balance proof. """
        self.token_network.update_transfer(
            channel_identifier=self.channel_identifier,
            partner=self.participant2,
            balance_hash=balance_hash,
            nonce=nonce,
            additional_hash=additional_hash,
            closing_signature=partner_signature,
            non_closing_signature=signature,
            given_block_identifier=block_identifier,
        )

    def unlock(
        self,
        sender: Address,
        receiver: Address,
        pending_locks: PendingLocksState,
        given_block_identifier: BlockSpecification,
    ) -> None:
        self.token_network.unlock(
            channel_identifier=self.channel_identifier,
            sender=sender,
            receiver=receiver,
            pending_locks=pending_locks,
            given_block_identifier=given_block_identifier,
        )

    def settle(
        self,
        transferred_amount: TokenAmount,
        locked_amount: TokenAmount,
        locksroot: Locksroot,
        partner_transferred_amount: TokenAmount,
        partner_locked_amount: TokenAmount,
        partner_locksroot: Locksroot,
        block_identifier: BlockSpecification,
    ) -> None:
        """ Settles the channel. """
        self.token_network.settle(
            channel_identifier=self.channel_identifier,
            transferred_amount=transferred_amount,
            locked_amount=locked_amount,
            locksroot=locksroot,
            partner=self.participant2,
            partner_transferred_amount=partner_transferred_amount,
            partner_locked_amount=partner_locked_amount,
            partner_locksroot=partner_locksroot,
            given_block_identifier=block_identifier,
        )

    def all_events_filter(
        self, from_block: BlockSpecification, to_block: BlockSpecification
    ) -> Filter:

        channel_topics: List[Optional[str]] = [
            None,  # event topic is any
            f"0x{self.channel_identifier:064x}",
        ]

        # This will match the events:
        # ChannelOpened, ChannelNewDeposit, ChannelWithdraw, ChannelClosed,
        # NonClosingBalanceProofUpdated, ChannelSettled, ChannelUnlocked
        channel_filter = self.token_network.client.new_filter(
            contract_address=Address(self.token_network.address),
            topics=channel_topics,
            from_block=from_block,
            to_block=to_block,
        )

        return channel_filter
