from raiden.transfer.state import (
    NettingChannelEndState,
    NettingChannelState,
    TransactionExecutionStatus,
)


def get_channel_state(
        token_address,
        token_network_address,
        reveal_timeout,
        netting_channel_proxy,
):
    channel_details = netting_channel_proxy.detail()

    our_state = NettingChannelEndState(
        channel_details['our_address'],
        channel_details['our_balance'],
    )
    partner_state = NettingChannelEndState(
        channel_details['partner_address'],
        channel_details['partner_balance'],
    )

    identifier = netting_channel_proxy.address
    settle_timeout = channel_details['settle_timeout']

    opened_block_number = netting_channel_proxy.opened()
    closed_block_number = netting_channel_proxy.closed()

    # ignore bad open block numbers
    if opened_block_number <= 0:
        return None

    # ignore negative closed block numbers
    if closed_block_number < 0:
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
        identifier,
        token_address,
        token_network_address,
        reveal_timeout,
        settle_timeout,
        our_state,
        partner_state,
        open_transaction,
        close_transaction,
        settle_transaction,
    )

    return channel
