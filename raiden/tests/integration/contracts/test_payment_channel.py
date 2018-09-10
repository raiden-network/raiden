import pytest
from eth_utils import decode_hex, encode_hex, to_canonical_address, to_checksum_address

from raiden.constants import EMPTY_HASH
from raiden.exceptions import ChannelOutdatedError
from raiden.network.proxies import PaymentChannel, TokenNetwork
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils import wait_blocks
from raiden.utils import privatekey_to_address
from raiden_contracts.constants import TEST_SETTLE_TIMEOUT_MIN
from raiden_libs.messages import BalanceProof
from raiden_libs.utils.signing import eth_sign


def test_payment_channel_proxy_basics(
        token_network_proxy,
        private_keys,
        token_proxy,
        chain_id,
        web3,
):
    token_network_address = to_canonical_address(token_network_proxy.proxy.contract.address)

    c1_client = JSONRPCClient(web3, private_keys[1])
    c2_client = JSONRPCClient(web3, private_keys[2])
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

    channel_filter = channel_proxy_1.all_events_filter(
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
        channel_identifier=channel_identifier,
        token_network_address=to_checksum_address(token_network_address),
        nonce=1,
        chain_id=chain_id,
        transferred_amount=transferred_amount,
    )
    balance_proof.signature = encode_hex(eth_sign(
        privkey=encode_hex(private_keys[1]),
        data=balance_proof.serialize_bin(),
    ))
    # correct close
    c2_token_network_proxy.close(
        channel_identifier=channel_identifier,
        partner=c1_client.sender,
        balance_hash=decode_hex(balance_proof.balance_hash),
        nonce=balance_proof.nonce,
        additional_hash=decode_hex(balance_proof.additional_hash),
        signature=decode_hex(balance_proof.signature),
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
        channel_identifier=channel_identifier,
        transferred_amount=0,
        locked_amount=0,
        locksroot=EMPTY_HASH,
        partner=c1_client.sender,
        partner_transferred_amount=transferred_amount,
        partner_locked_amount=0,
        partner_locksroot=EMPTY_HASH,
    )
    assert channel_proxy_1.settled() is True
    assert channel_proxy_2.settled() is True

    events = channel_filter.get_all_entries()

    assert len(events) == 4  # ChannelOpened, ChannelNewDeposit, ChannelClosed, ChannelSettled


def test_payment_channel_outdated_channel_close(
        token_network_proxy,
        private_keys,
        chain_id,
        web3,
):
    token_network_address = to_canonical_address(token_network_proxy.proxy.contract.address)

    partner = privatekey_to_address(private_keys[0])

    client = JSONRPCClient(web3, private_keys[1])
    token_network_proxy = TokenNetwork(
        client,
        token_network_address,
    )

    # create a channel
    channel_identifier = token_network_proxy.new_netting_channel(
        partner,
        TEST_SETTLE_TIMEOUT_MIN,
    )
    assert channel_identifier is not None

    # create channel proxies
    channel_proxy_1 = PaymentChannel(token_network_proxy, channel_identifier)

    channel_filter = channel_proxy_1.all_events_filter(
        from_block=web3.eth.blockNumber,
        to_block='latest',
    )

    assert channel_proxy_1.channel_identifier == channel_identifier

    assert channel_proxy_1.opened() is True

    # balance proof by c1
    balance_proof = BalanceProof(
        channel_identifier=channel_identifier,
        token_network_address=to_checksum_address(token_network_address),
        nonce=0,
        chain_id=chain_id,
        transferred_amount=0,
    )
    balance_proof.signature = encode_hex(eth_sign(
        privkey=encode_hex(private_keys[0]),
        data=balance_proof.serialize_bin(),
    ))
    # correct close
    token_network_proxy.close(
        channel_identifier=channel_identifier,
        partner=partner,
        balance_hash=bytes(32),
        nonce=balance_proof.nonce,
        additional_hash=bytes(32),
        signature=decode_hex(balance_proof.signature),
    )
    assert channel_proxy_1.closed() is True

    events = channel_filter.get_all_entries()
    assert len(events) == 2  # ChannelOpened, ChannelClosed

    # check the settlement timeouts again
    assert channel_proxy_1.settle_timeout() == TEST_SETTLE_TIMEOUT_MIN

    # update transfer
    wait_blocks(client.web3, TEST_SETTLE_TIMEOUT_MIN)

    token_network_proxy.settle(
        channel_identifier=channel_identifier,
        transferred_amount=0,
        locked_amount=0,
        locksroot=EMPTY_HASH,
        partner=partner,
        partner_transferred_amount=0,
        partner_locked_amount=0,
        partner_locksroot=EMPTY_HASH,
    )
    assert channel_proxy_1.settled() is True

    events = channel_filter.get_all_entries()

    assert len(events) == 3  # ChannelOpened, ChannelClosed, ChannelSettled

    # Create a new channel with a different identifier
    # create a channel
    new_channel_identifier = token_network_proxy.new_netting_channel(
        partner,
        TEST_SETTLE_TIMEOUT_MIN,
    )
    assert new_channel_identifier is not None
    # create channel proxies
    channel_proxy_2 = PaymentChannel(token_network_proxy, new_channel_identifier)

    assert channel_proxy_2.channel_identifier == new_channel_identifier
    assert channel_proxy_2.opened() is True

    with pytest.raises(ChannelOutdatedError):
        token_network_proxy.close(
            channel_identifier=channel_identifier,
            partner=partner,
            balance_hash=bytes(32),
            nonce=balance_proof.nonce,
            additional_hash=bytes(32),
            signature=decode_hex(balance_proof.signature),
        )
