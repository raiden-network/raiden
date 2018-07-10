from raiden.transfer.state import (
    NettingChannelEndState,
    NettingChannelState,
    TransactionExecutionStatus,
)


def get_channel_state(
        token_address,
        token_network_address,
        reveal_timeout,
        payment_channel_proxy,
        opened_block_number,
):
    channel_details = payment_channel_proxy.detail()

    our_state = NettingChannelEndState(
        channel_details['our_address'],
        channel_details['our_deposit'],
    )
    partner_state = NettingChannelEndState(
        channel_details['partner_address'],
        channel_details['partner_deposit'],
    )

    identifier = payment_channel_proxy.channel_identifier
    settle_timeout = payment_channel_proxy.settle_timeout()

    closed_block_number = None

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
        chain_id=channel_details['chain_id'],
        token_address=token_address,
        token_network_identifier=token_network_address,
        reveal_timeout=reveal_timeout,
        settle_timeout=settle_timeout,
        our_state=our_state,
        partner_state=partner_state,
        open_transaction=open_transaction,
        close_transaction=close_transaction,
        settle_transaction=settle_transaction,
    )

    return channel
