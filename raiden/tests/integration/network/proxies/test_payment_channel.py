import pytest

from raiden.constants import EMPTY_HASH, EMPTY_SIGNATURE, LOCKSROOT_OF_NO_LOCKS
from raiden.exceptions import (
    BrokenPreconditionError,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
)
from raiden.network.blockchain_service import BlockChainService
from raiden.network.rpc.client import JSONRPCClient
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.utils import privatekey_to_address
from raiden_contracts.constants import TEST_SETTLE_TIMEOUT_MIN


def test_payment_channel_proxy_basics(
    token_network_proxy, token_proxy, chain_id, private_keys, web3, contract_manager
):
    token_network_address = token_network_proxy.address
    partner = privatekey_to_address(private_keys[0])

    client = JSONRPCClient(web3, private_keys[1])
    chain = BlockChainService(jsonrpc_client=client, contract_manager=contract_manager)
    token_network_proxy = chain.token_network(address=token_network_address)
    start_block = web3.eth.blockNumber

    channel_identifier = token_network_proxy.new_netting_channel(
        partner=partner, settle_timeout=TEST_SETTLE_TIMEOUT_MIN, given_block_identifier="latest"
    )
    assert channel_identifier is not None

    channel_proxy_1 = chain.payment_channel(
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_id,
            token_network_address=token_network_address,
            channel_identifier=channel_identifier,
        )
    )

    channel_filter = channel_proxy_1.all_events_filter(from_block=start_block, to_block="latest")

    assert channel_proxy_1.channel_identifier == channel_identifier
    assert channel_proxy_1.opened("latest") is True

    # Test deposit
    initial_token_balance = 100
    token_proxy.transfer(client.address, initial_token_balance)
    assert token_proxy.balance_of(client.address) == initial_token_balance
    assert token_proxy.balance_of(partner) == 0
    channel_proxy_1.set_total_deposit(total_deposit=10, block_identifier="latest")

    assert len(channel_filter.get_all_entries()) == 2  # ChannelOpened, ChannelNewDeposit
    block_before_close = web3.eth.blockNumber

    channel_proxy_1.close(
        nonce=0,
        balance_hash=EMPTY_HASH,
        additional_hash=EMPTY_HASH,
        signature=EMPTY_SIGNATURE,
        block_identifier="latest",
    )
    assert channel_proxy_1.closed("latest") is True
    # ChannelOpened, ChannelNewDeposit, ChannelClosed
    assert len(channel_filter.get_all_entries()) == 3

    # check the settlement timeouts again
    assert channel_proxy_1.settle_timeout() == TEST_SETTLE_TIMEOUT_MIN

    # update transfer -- we need to wait on +1 since we use the latest block on parity for
    # estimate gas and at the time the latest block is the settle timeout block.
    # More info: https://github.com/raiden-network/raiden/pull/3699#discussion_r270477227
    chain.wait_until_block(target_block_number=client.block_number() + TEST_SETTLE_TIMEOUT_MIN + 1)

    channel_proxy_1.settle(
        transferred_amount=0,
        locked_amount=0,
        locksroot=LOCKSROOT_OF_NO_LOCKS,
        partner_transferred_amount=0,
        partner_locked_amount=0,
        partner_locksroot=LOCKSROOT_OF_NO_LOCKS,
        block_identifier="latest",
    )
    assert channel_proxy_1.settled("latest") is True
    # ChannelOpened, ChannelNewDeposit, ChannelClosed, ChannelSettled
    assert len(channel_filter.get_all_entries()) == 4

    new_channel_identifier = token_network_proxy.new_netting_channel(
        partner=partner, settle_timeout=TEST_SETTLE_TIMEOUT_MIN, given_block_identifier="latest"
    )
    assert new_channel_identifier is not None

    channel_proxy_2 = chain.payment_channel(
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_id,
            token_network_address=token_network_address,
            channel_identifier=new_channel_identifier,
        )
    )

    assert channel_proxy_2.channel_identifier == new_channel_identifier
    assert channel_proxy_2.opened("latest") is True

    msg = "The channel was already closed, the second call must fail"
    with pytest.raises(RaidenRecoverableError, message=msg):
        channel_proxy_1.close(
            nonce=0,
            balance_hash=EMPTY_HASH,
            additional_hash=EMPTY_HASH,
            signature=EMPTY_SIGNATURE,
            block_identifier=block_before_close,
        )

    msg = "The channel is not open at latest, this must raise"
    with pytest.raises(RaidenUnrecoverableError, message=msg):
        channel_proxy_1.close(
            nonce=0,
            balance_hash=EMPTY_HASH,
            additional_hash=EMPTY_HASH,
            signature=EMPTY_SIGNATURE,
            block_identifier="latest",
        )

    msg = (
        "The channel was not opened at the provided block (latest). "
        "This call should never have been attempted."
    )
    with pytest.raises(BrokenPreconditionError, message=msg):
        channel_proxy_1.set_total_deposit(total_deposit=20, block_identifier="latest")
