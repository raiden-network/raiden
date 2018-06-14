import pytest
import gevent
from eth_utils import (
    to_canonical_address,
    encode_hex,
    decode_hex,
    to_checksum_address
)
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.proxies import TokenNetwork
from raiden.constants import (
    NETTINGCHANNEL_SETTLE_TIMEOUT_MIN,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MAX,
)
from raiden.exceptions import (
    InvalidSettleTimeout,
    SamePeerAddress,
    DuplicatedChannelError,
    TransactionThrew,
    ChannelIncorrectStateError,
)
from raiden_libs.messages import BalanceProof
from raiden_libs.utils.signing import sign_data

EMPTY_HASH = b'\x00' * 32


def wait_blocks(web3, blocks):
    target_block = web3.eth.blockNumber + blocks
    while web3.eth.blockNumber < target_block:
        gevent.sleep(0.5)


def test_token_network_proxy(
    token_network_proxy,
    private_keys,
    blockchain_rpc_ports,
    token_proxy,
    chain_id,
):
    token_network_address = to_canonical_address(token_network_proxy.proxy.contract.address)

    c1_client = JSONRPCClient(
        '0.0.0.0',
        blockchain_rpc_ports[0],
        private_keys[1],
    )
    c2_client = JSONRPCClient(
        '0.0.0.0',
        blockchain_rpc_ports[0],
        private_keys[2],
    )
    c1_token_network_proxy = TokenNetwork(
        c1_client,
        token_network_address,
    )

    # instantiating a new channel - test basic assumptions
    assert c1_token_network_proxy.channel_exists(c2_client.sender) is False
    # test timeout limits
    with pytest.raises(InvalidSettleTimeout):
        c1_token_network_proxy.new_netting_channel(
            c2_client.sender,
            NETTINGCHANNEL_SETTLE_TIMEOUT_MIN - 1
        )
    with pytest.raises(InvalidSettleTimeout):
        c1_token_network_proxy.new_netting_channel(
            c2_client.sender,
            NETTINGCHANNEL_SETTLE_TIMEOUT_MAX + 1
        )
    # channel to self
    with pytest.raises(SamePeerAddress):
        c1_token_network_proxy.new_netting_channel(
            c1_client.sender,
            NETTINGCHANNEL_SETTLE_TIMEOUT_MIN
        )
    # actually create a channel
    channel_identifier = c1_token_network_proxy.new_netting_channel(
        c2_client.sender,
        NETTINGCHANNEL_SETTLE_TIMEOUT_MIN
    )
    assert channel_identifier is not None
    # multiple channels with the same peer are not allowed
    with pytest.raises(DuplicatedChannelError):
        c1_token_network_proxy.new_netting_channel(
            c2_client.sender,
            NETTINGCHANNEL_SETTLE_TIMEOUT_MIN
        )
    assert c1_token_network_proxy.channel_exists(c2_client.sender) is True

    # channel is open.
    # deposit with no balance
    with pytest.raises(ValueError):
        c1_token_network_proxy.deposit(
            10,
            c2_client.sender
        )
    # test deposits
    token_proxy.transfer(c1_client.sender, 100)
    # no negative deposit
    with pytest.raises(ValueError):
        c1_token_network_proxy.deposit(
            -1,
            c2_client.sender
        )
    # actual deposit
    c1_token_network_proxy.deposit(
        10,
        c2_client.sender
    )
    transferred_amount = 3
    balance_proof = BalanceProof(
        channel_identifier=encode_hex(channel_identifier),
        token_network_address=to_checksum_address(token_network_address),
        nonce=1,
        chain_id=chain_id,
        transferred_amount=transferred_amount,
    )
    balance_proof.signature = encode_hex(
        sign_data(encode_hex(private_keys[2]), balance_proof.serialize_bin())
    )
    # close with invalid signature
    with pytest.raises(TransactionThrew):
        c1_token_network_proxy.close(
            c2_client.sender,
            balance_proof.nonce,
            balance_proof.balance_hash,
            balance_proof.additional_hash,
            b'\x11' * 65,
        )
    # correct close
    c1_token_network_proxy.close(
        c2_client.sender,
        balance_proof.nonce,
        balance_proof.balance_hash,
        balance_proof.additional_hash,
        decode_hex(balance_proof.signature)
    )
    # closing already closed channel
    with pytest.raises(ChannelIncorrectStateError):
        c1_token_network_proxy.close(
            c2_client.sender,
            balance_proof.nonce,
            balance_proof.balance_hash,
            balance_proof.additional_hash,
            decode_hex(balance_proof.signature)
        )
    # update transfer
    c1_token_network_proxy.update_transfer(
    )
    wait_blocks(c1_client.web3, NETTINGCHANNEL_SETTLE_TIMEOUT_MIN)

    c1_token_network_proxy.settle(
        transferred_amount,
        0,
        EMPTY_HASH,
        c2_client.sender,
        0,
        0,
        EMPTY_HASH,
    )
