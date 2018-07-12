from eth_utils import (
    to_canonical_address,
    encode_hex,
    decode_hex,
    to_checksum_address,
)
from raiden_libs.utils.signing import sign_data
from raiden_libs.messages import BalanceProof
from raiden_contracts.constants import TEST_SETTLE_TIMEOUT_MIN

from raiden.network.rpc.client import JSONRPCClient
from raiden.network.proxies import TokenNetwork, PaymentChannel
from raiden.constants import EMPTY_HASH
from raiden.tests.utils import wait_blocks


def test_payment_channel_proxy_basics(
    token_network_proxy,
    private_keys,
    blockchain_rpc_ports,
    token_proxy,
    chain_id,
    web3,
):
    token_network_address = to_canonical_address(token_network_proxy.proxy.contract.address)

    c1_client = JSONRPCClient(
        '0.0.0.0',
        blockchain_rpc_ports[0],
        private_keys[1],
        web3=web3,
    )
    c2_client = JSONRPCClient(
        '0.0.0.0',
        blockchain_rpc_ports[0],
        private_keys[2],
        web3=web3,
    )
    c1_token_network_proxy = TokenNetwork(
        c1_client,
        token_network_address,
    )
    c2_token_network_proxy = TokenNetwork(
        c2_client,
        token_network_address,
    )

    # create a channel
    channel_identifier = c1_token_network_proxy.new_netting_channel(
        c2_client.sender,
        TEST_SETTLE_TIMEOUT_MIN,
    )
    assert channel_identifier is not None

    # create channel proxies
    channel_proxy_1 = PaymentChannel(c1_token_network_proxy, channel_identifier)
    channel_proxy_2 = PaymentChannel(c2_token_network_proxy, channel_identifier)

    channel_filter, unlock_filter = channel_proxy_1.all_events_filter(
        from_block=web3.eth.blockNumber,
        to_block='latest',
    )

    assert channel_proxy_1.channel_identifier == channel_identifier
    assert channel_proxy_2.channel_identifier == channel_identifier

    assert channel_proxy_1.opened() is True
    assert channel_proxy_2.opened() is True

    # check the settlement timeouts
    assert channel_proxy_1.settle_timeout() == channel_proxy_2.settle_timeout()
    assert channel_proxy_1.settle_timeout() == TEST_SETTLE_TIMEOUT_MIN

    events = channel_filter.get_all_entries()
    assert len(events) == 1  # ChannelOpened

    # test deposits
    initial_token_balance = 100
    token_proxy.transfer(c1_client.sender, initial_token_balance)
    initial_balance_c1 = token_proxy.balance_of(c1_client.sender)
    assert initial_balance_c1 == initial_token_balance
    initial_balance_c2 = token_proxy.balance_of(c2_client.sender)
    assert initial_balance_c2 == 0

    # actual deposit
    channel_proxy_1.set_total_deposit(10)

    events = channel_filter.get_all_entries()
    assert len(events) == 2  # ChannelOpened, ChannelNewDeposit

    # balance proof by c2
    transferred_amount = 3
    balance_proof = BalanceProof(
        channel_identifier=encode_hex(channel_identifier),
        token_network_address=to_checksum_address(token_network_address),
        nonce=1,
        chain_id=chain_id,
        transferred_amount=transferred_amount,
    )
    balance_proof.signature = encode_hex(
        sign_data(encode_hex(private_keys[1]), balance_proof.serialize_bin()),
    )
    # correct close
    c2_token_network_proxy.close(
        c1_client.sender,
        balance_proof.nonce,
        decode_hex(balance_proof.balance_hash),
        decode_hex(balance_proof.additional_hash),
        decode_hex(balance_proof.signature),
    )
    assert channel_proxy_1.closed() is True
    assert channel_proxy_2.closed() is True

    events = channel_filter.get_all_entries()
    assert len(events) == 3  # ChannelOpened, ChannelNewDeposit, ChannelClosed

    # check the settlement timeouts again
    assert channel_proxy_1.settle_timeout() == channel_proxy_2.settle_timeout()
    assert channel_proxy_1.settle_timeout() == TEST_SETTLE_TIMEOUT_MIN

    # update transfer
    wait_blocks(c1_client.web3, TEST_SETTLE_TIMEOUT_MIN)

    c2_token_network_proxy.settle(
        0,
        0,
        EMPTY_HASH,
        c1_client.sender,
        transferred_amount,
        0,
        EMPTY_HASH,
    )
    assert channel_proxy_1.settled() is True
    assert channel_proxy_2.settled() is True

    events = channel_filter.get_all_entries()

    assert len(events) == 4  # ChannelOpened, ChannelNewDeposit, ChannelClosed, ChannelSettled
