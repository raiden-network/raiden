from raiden.transfer.state import (
    NettingChannelEndState,
    NettingChannelState,
    TransactionExecutionStatus,
)
from raiden.utils.typing import (
    BlockHash,
    BlockNumber,
    BlockTimeout,
    PaymentNetworkID,
    TokenAddress,
    TokenNetworkAddress,
    TokenNetworkID,
)


def get_channel_state(
        token_address: TokenAddress,
        payment_network_identifier: PaymentNetworkID,
        token_network_address: TokenNetworkAddress,
        reveal_timeout: BlockTimeout,
        payment_channel_proxy,
        opened_block_number: BlockNumber,
        opened_block_hash: BlockHash,
):
    channel_details = payment_channel_proxy.detail(opened_block_hash)

    our_state = NettingChannelEndState(
        channel_details.participants_data.our_details.address,
        channel_details.participants_data.our_details.deposit,
    )
    partner_state = NettingChannelEndState(
        channel_details.participants_data.partner_details.address,
        channel_details.participants_data.partner_details.deposit,
    )

    identifier = payment_channel_proxy.channel_identifier
    settle_timeout = payment_channel_proxy.settle_timeout()
    closed_block_number = payment_channel_proxy.close_block_number()

    # ignore bad open block numbers
    if opened_block_number <= 0:
        return None

    open_transaction = TransactionExecutionStatus(
        None,
        opened_block_number,
        TransactionExecutionStatus.SUCCESS,
    )

    if closed_block_number:
        close_transaction = TransactionExecutionStatus(
            None,
            closed_block_number,
            TransactionExecutionStatus.SUCCESS,
        )
    else:
        close_transaction = None

    # For the current implementation the channel is a smart contract that
    # will be killed on settle.
    settle_transaction = None

    channel = NettingChannelState(
        identifier=identifier,
        chain_id=channel_details.chain_id,
        token_address=token_address,
        payment_network_identifier=payment_network_identifier,
        token_network_identifier=TokenNetworkID(token_network_address),
        reveal_timeout=reveal_timeout,
        settle_timeout=settle_timeout,
        our_state=our_state,
        partner_state=partner_state,
        open_transaction=open_transaction,
        close_transaction=close_transaction,
        settle_transaction=settle_transaction,
    )

    return channel
