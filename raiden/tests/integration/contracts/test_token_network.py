import pytest
from eth_utils import (
    to_canonical_address,
    encode_hex,
    decode_hex,
    to_checksum_address,
)
from raiden_contracts.constants import (
    TEST_SETTLE_TIMEOUT_MIN,
    TEST_SETTLE_TIMEOUT_MAX,
)
from raiden_libs.messages import BalanceProof
from raiden_libs.utils.signing import sign_data

from raiden.constants import EMPTY_HASH
from raiden.exceptions import (
    InvalidSettleTimeout,
    SamePeerAddress,
    DuplicatedChannelError,
    TransactionThrew,
    ChannelIncorrectStateError,
    DepositMismatch,
)
from raiden.network.proxies import TokenNetwork
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils import wait_blocks


def test_token_network_deposit_race(
        token_network_proxy,
        private_keys,
        blockchain_rpc_ports,
        token_proxy,
        web3,
):
    assert token_network_proxy.settlement_timeout_min() == TEST_SETTLE_TIMEOUT_MIN
    assert token_network_proxy.settlement_timeout_max() == TEST_SETTLE_TIMEOUT_MAX

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
    token_proxy.transfer(c1_client.sender, 10)
    channel_identifier = c1_token_network_proxy.new_netting_channel(
        c2_client.sender,
        TEST_SETTLE_TIMEOUT_MIN,
    )
    assert channel_identifier is not None

    c1_token_network_proxy.set_total_deposit(
        channel_identifier,
        2,
        c2_client.sender,
    )
    with pytest.raises(DepositMismatch):
        c1_token_network_proxy.set_total_deposit(
            channel_identifier,
            1,
            c2_client.sender,
        )


def test_token_network_proxy_basics(
        token_network_proxy,
        private_keys,
        blockchain_rpc_ports,
        token_proxy,
        chain_id,
        web3,
):
    # check settlement timeouts
    assert token_network_proxy.settlement_timeout_min() == TEST_SETTLE_TIMEOUT_MIN
    assert token_network_proxy.settlement_timeout_max() == TEST_SETTLE_TIMEOUT_MAX

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

    # instantiating a new channel - test basic assumptions
    assert c1_token_network_proxy.channel_exists(c1_client.sender, c2_client.sender) is False
    assert c1_token_network_proxy.channel_is_opened(c1_client.sender, c2_client.sender) is False
    assert c1_token_network_proxy.channel_is_closed(c1_client.sender, c2_client.sender) is False
    # test timeout limits
    with pytest.raises(InvalidSettleTimeout):
        c1_token_network_proxy.new_netting_channel(
            c2_client.sender,
            TEST_SETTLE_TIMEOUT_MIN - 1,
        )
    with pytest.raises(InvalidSettleTimeout):
        c1_token_network_proxy.new_netting_channel(
            c2_client.sender,
            TEST_SETTLE_TIMEOUT_MAX + 1,
        )
    # channel to self
    with pytest.raises(SamePeerAddress):
        c1_token_network_proxy.new_netting_channel(
            c1_client.sender,
            TEST_SETTLE_TIMEOUT_MIN,
        )
    # actually create a channel
    channel_identifier = c1_token_network_proxy.new_netting_channel(
        c2_client.sender,
        TEST_SETTLE_TIMEOUT_MIN,
    )
    assert channel_identifier is not None
    # multiple channels with the same peer are not allowed
    with pytest.raises(DuplicatedChannelError):
        c1_token_network_proxy.new_netting_channel(
            c2_client.sender,
            TEST_SETTLE_TIMEOUT_MIN,
        )
    assert c1_token_network_proxy.channel_exists(c1_client.sender, c2_client.sender) is True
    assert c1_token_network_proxy.channel_is_opened(c1_client.sender, c2_client.sender) is True

    # channel is open.
    # deposit with no balance
    with pytest.raises(ValueError):
        c1_token_network_proxy.set_total_deposit(
            channel_identifier,
            10,
            c2_client.sender,
        )
    # test deposits
    initial_token_balance = 100
    token_proxy.transfer(c1_client.sender, initial_token_balance)
    initial_balance_c1 = token_proxy.balance_of(c1_client.sender)
    assert initial_balance_c1 == initial_token_balance
    initial_balance_c2 = token_proxy.balance_of(c2_client.sender)
    assert initial_balance_c2 == 0
    # no negative deposit
    with pytest.raises(DepositMismatch):
        c1_token_network_proxy.set_total_deposit(
            channel_identifier,
            -1,
            c2_client.sender,
        )
    # actual deposit
    c1_token_network_proxy.set_total_deposit(
        channel_identifier,
        10,
        c2_client.sender,
    )
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
    # close with invalid signature
    with pytest.raises(TransactionThrew):
        c2_token_network_proxy.close(
            channel_identifier,
            c1_client.sender,
            balance_proof.nonce,
            decode_hex(balance_proof.balance_hash),
            decode_hex(balance_proof.additional_hash),
            b'\x11' * 65,
        )
    # correct close
    c2_token_network_proxy.close(
        channel_identifier,
        c1_client.sender,
        balance_proof.nonce,
        decode_hex(balance_proof.balance_hash),
        decode_hex(balance_proof.additional_hash),
        decode_hex(balance_proof.signature),
    )
    assert c1_token_network_proxy.channel_is_closed(c1_client.sender, c2_client.sender) is True
    assert c1_token_network_proxy.channel_exists(c1_client.sender, c2_client.sender) is True
    # closing already closed channel
    with pytest.raises(ChannelIncorrectStateError):
        c2_token_network_proxy.close(
            channel_identifier,
            c1_client.sender,
            balance_proof.nonce,
            decode_hex(balance_proof.balance_hash),
            decode_hex(balance_proof.additional_hash),
            decode_hex(balance_proof.signature),
        )
    # update transfer
    wait_blocks(c1_client.web3, TEST_SETTLE_TIMEOUT_MIN)

    # try to settle using incorrect data
    with pytest.raises(ChannelIncorrectStateError):
        c2_token_network_proxy.settle(
            channel_identifier,
            1,
            0,
            EMPTY_HASH,
            c1_client.sender,
            transferred_amount,
            0,
            EMPTY_HASH,
        )
    c2_token_network_proxy.settle(
        channel_identifier,
        0,
        0,
        EMPTY_HASH,
        c1_client.sender,
        transferred_amount,
        0,
        EMPTY_HASH,
    )
    assert c1_token_network_proxy.channel_exists(c1_client.sender, c2_client.sender) is False
    assert token_proxy.balance_of(c1_client.sender) == (initial_balance_c1 - transferred_amount)
    assert token_proxy.balance_of(c2_client.sender) == (initial_balance_c2 + transferred_amount)


def test_token_network_proxy_update_transfer(
        token_network_proxy,
        private_keys,
        blockchain_rpc_ports,
        token_proxy,
        chain_id,
        web3,
):
    """Tests channel lifecycle, with `update_transfer` before settling"""
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
    # deposit to the channel
    initial_balance = 100
    token_proxy.transfer(c1_client.sender, initial_balance)
    token_proxy.transfer(c2_client.sender, initial_balance)
    initial_balance_c1 = token_proxy.balance_of(c1_client.sender)
    assert initial_balance_c1 == initial_balance
    initial_balance_c2 = token_proxy.balance_of(c2_client.sender)
    assert initial_balance_c2 == initial_balance
    c1_token_network_proxy.set_total_deposit(
        channel_identifier,
        10,
        c2_client.sender,
    )
    c2_token_network_proxy.set_total_deposit(
        channel_identifier,
        10,
        c1_client.sender,
    )
    # balance proof signed by c1
    transferred_amount_c1 = 1
    transferred_amount_c2 = 3
    balance_proof_c1 = BalanceProof(
        channel_identifier=encode_hex(channel_identifier),
        token_network_address=to_checksum_address(token_network_address),
        nonce=1,
        chain_id=chain_id,
        transferred_amount=transferred_amount_c1,
    )
    balance_proof_c1.signature = encode_hex(
        sign_data(encode_hex(private_keys[1]), balance_proof_c1.serialize_bin()),
    )
    # balance proof signed by c2
    balance_proof_c2 = BalanceProof(
        channel_identifier=encode_hex(channel_identifier),
        token_network_address=to_checksum_address(token_network_address),
        nonce=2,
        chain_id=chain_id,
        transferred_amount=transferred_amount_c2,
    )
    balance_proof_c2.signature = encode_hex(
        sign_data(encode_hex(private_keys[2]), balance_proof_c2.serialize_bin()),
    )
    # close by c1
    c1_token_network_proxy.close(
        channel_identifier,
        c2_client.sender,
        balance_proof_c2.nonce,
        decode_hex(balance_proof_c2.balance_hash),
        decode_hex(balance_proof_c2.additional_hash),
        decode_hex(balance_proof_c2.signature),
    )

    # using invalid non-closing signature
    # Usual mistake when calling update Transfer - balance proof signature is missing in the data
    non_closing_data = balance_proof_c1.serialize_bin()
    non_closing_signature = sign_data(
        encode_hex(c2_client.privkey),
        non_closing_data,
    )
    with pytest.raises(TransactionThrew):
        c2_token_network_proxy.update_transfer(
            channel_identifier,
            c1_client.sender,
            balance_proof_c1.nonce,
            decode_hex(balance_proof_c1.balance_hash),
            decode_hex(balance_proof_c1.additional_hash),
            decode_hex(balance_proof_c1.signature),
            non_closing_signature,
        )

    non_closing_data = balance_proof_c1.serialize_bin() + decode_hex(balance_proof_c1.signature)
    non_closing_signature = sign_data(
        encode_hex(c2_client.privkey),
        non_closing_data,
    )
    c2_token_network_proxy.update_transfer(
        channel_identifier,
        c1_client.sender,
        balance_proof_c1.nonce,
        decode_hex(balance_proof_c1.balance_hash),
        decode_hex(balance_proof_c1.additional_hash),
        decode_hex(balance_proof_c1.signature),
        non_closing_signature,
    )
    wait_blocks(c1_client.web3, TEST_SETTLE_TIMEOUT_MIN)

    # settling with an invalid amount
    with pytest.raises(ChannelIncorrectStateError):
        c1_token_network_proxy.settle(
            channel_identifier,
            2,
            0,
            EMPTY_HASH,
            c2_client.sender,
            2,
            0,
            EMPTY_HASH,
        )
    # proper settle
    c1_token_network_proxy.settle(
        channel_identifier,
        transferred_amount_c1,
        0,
        EMPTY_HASH,
        c2_client.sender,
        transferred_amount_c2,
        0,
        EMPTY_HASH,
    )
    assert (token_proxy.balance_of(c2_client.sender) ==
            (initial_balance_c2 + transferred_amount_c1 - transferred_amount_c2))
    assert (token_proxy.balance_of(c1_client.sender) ==
            (initial_balance_c1 + transferred_amount_c2 - transferred_amount_c1))
