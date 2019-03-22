from raiden.transfer.state import (
    NettingChannelEndState,
    NettingChannelState,
    TransactionExecutionStatus,
)
from raiden.utils import CanonicalIdentifier
from raiden.utils.typing import (
    BlockNumber,
    BlockTimeout,
    PaymentNetworkID,
    TokenAddress,
    TokenNetworkAddress,
)


def get_channel_state(
        token_address: TokenAddress,
        payment_network_identifier: PaymentNetworkID,
        token_network_address: TokenNetworkAddress,
        reveal_timeout: BlockTimeout,
        payment_channel_proxy,
        opened_block_number: BlockNumber,
):
    # Here we have to query the latest state because if we query with an older block
    # state (e.g. opened_block_number) the state may have been pruned which will
    # lead to an error.
    latest_block_hash = payment_channel_proxy.client.blockhash_from_blocknumber('latest')
    channel_details = payment_channel_proxy.detail(latest_block_hash)

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
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=channel_details.chain_id,
            token_network_address=token_network_address,
            channel_identifier=identifier,
        ),
        token_address=token_address,
        payment_network_identifier=payment_network_identifier,
        reveal_timeout=reveal_timeout,
        settle_timeout=settle_timeout,
        our_state=our_state,
        partner_state=partner_state,
        open_transaction=open_transaction,
        close_transaction=close_transaction,
        settle_transaction=settle_transaction,
    )

    return channel
