from typing import TYPE_CHECKING

from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.transfer.state import (
    NettingChannelEndState,
    NettingChannelState,
    TransactionExecutionStatus,
)
from raiden.utils import typing

if TYPE_CHECKING:
    from raiden.network.proxies.payment_channel import ChannelDetails, PaymentChannel


def create_channel_state_from_blockchain_data(
    payment_network_address: typing.PaymentNetworkAddress,
    token_network_address: typing.TokenNetworkAddress,
    token_address: typing.TokenAddress,
    channel_details: "ChannelDetails",
    identifier: typing.ChannelID,
    reveal_timeout: typing.BlockTimeout,
    settle_timeout: typing.BlockTimeout,
    opened_block_number: typing.BlockNumber,
    closed_block_number: typing.Optional[typing.BlockNumber],
    fee_schedule: FeeScheduleState,
) -> typing.Optional[NettingChannelState]:
    our_state = NettingChannelEndState(
        channel_details.participants_data.our_details.address,
        typing.Balance(channel_details.participants_data.our_details.deposit),
    )
    partner_state = NettingChannelEndState(
        channel_details.participants_data.partner_details.address,
        typing.Balance(channel_details.participants_data.partner_details.deposit),
    )

    # ignore bad open block numbers
    if opened_block_number <= 0:
        return None

    open_transaction = TransactionExecutionStatus(
        None, opened_block_number, TransactionExecutionStatus.SUCCESS
    )

    close_transaction: typing.Optional[TransactionExecutionStatus] = None
    if closed_block_number:
        close_transaction = TransactionExecutionStatus(
            None, closed_block_number, TransactionExecutionStatus.SUCCESS
        )

    # For the current implementation the channel is a smart contract that
    # will be killed on settle.
    settle_transaction = None

    channel = NettingChannelState(
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=channel_details.chain_id,
            token_network_address=token_network_address,
            channel_identifier=identifier,
        ),
        token_address=token_address,
        payment_network_address=payment_network_address,
        reveal_timeout=reveal_timeout,
        settle_timeout=settle_timeout,
        fee_schedule=fee_schedule,
        our_state=our_state,
        partner_state=partner_state,
        open_transaction=open_transaction,
        close_transaction=close_transaction,
        settle_transaction=settle_transaction,
    )

    return channel


def get_channel_state(
    token_address: typing.TokenAddress,
    payment_network_address: typing.PaymentNetworkAddress,
    token_network_address: typing.TokenNetworkAddress,
    reveal_timeout: typing.BlockTimeout,
    payment_channel_proxy: "PaymentChannel",
    opened_block_number: typing.BlockNumber,
    fee_schedule: FeeScheduleState,
):  # pragma: no unittest
    # Here we have to query the latest state because if we query with an older block
    # state (e.g. opened_block_number) the state may have been pruned which will
    # lead to an error.
    latest_block_hash = payment_channel_proxy.client.blockhash_from_blocknumber("latest")

    return create_channel_state_from_blockchain_data(
        payment_network_address=payment_network_address,
        token_network_address=token_network_address,
        token_address=token_address,
        channel_details=payment_channel_proxy.detail(latest_block_hash),
        identifier=payment_channel_proxy.channel_identifier,
        reveal_timeout=reveal_timeout,
        settle_timeout=payment_channel_proxy.settle_timeout(),
        opened_block_number=opened_block_number,
        closed_block_number=payment_channel_proxy.close_block_number(),
        fee_schedule=fee_schedule,
    )
