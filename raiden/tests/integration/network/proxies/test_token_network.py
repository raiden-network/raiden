import random

import pytest
from eth_utils import decode_hex, encode_hex, to_canonical_address, to_checksum_address

from raiden.constants import EMPTY_HASH, EMPTY_SIGNATURE, STATE_PRUNING_AFTER_BLOCKS
from raiden.exceptions import (
    DepositMismatch,
    DuplicatedChannelError,
    InvalidSettleTimeout,
    NoStateForBlockIdentifier,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
    SamePeerAddress,
)
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies.token_network import TokenNetwork
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.integration.network.proxies import BalanceProof
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import T_ChannelID
from raiden_contracts.constants import (
    TEST_SETTLE_TIMEOUT_MAX,
    TEST_SETTLE_TIMEOUT_MIN,
    MessageTypeId,
)

SIGNATURE_SIZE_IN_BITS = 520


def test_token_network_deposit_race(
    token_network_proxy, private_keys, token_proxy, web3, contract_manager
):
    assert token_network_proxy.settlement_timeout_min() == TEST_SETTLE_TIMEOUT_MIN
    assert token_network_proxy.settlement_timeout_max() == TEST_SETTLE_TIMEOUT_MAX

    token_network_address = to_canonical_address(token_network_proxy.proxy.contract.address)

    c1_client = JSONRPCClient(web3, private_keys[1])
    c2_client = JSONRPCClient(web3, private_keys[2])
    c1_token_network_proxy = TokenNetwork(
        jsonrpc_client=c1_client,
        token_network_address=token_network_address,
        contract_manager=contract_manager,
    )
    token_proxy.transfer(c1_client.address, 10)
    channel_identifier = c1_token_network_proxy.new_netting_channel(
        partner=c2_client.address,
        settle_timeout=TEST_SETTLE_TIMEOUT_MIN,
        given_block_identifier="latest",
    )
    assert channel_identifier is not None

    c1_token_network_proxy.set_total_deposit(
        given_block_identifier="latest",
        channel_identifier=channel_identifier,
        total_deposit=2,
        partner=c2_client.address,
    )
    with pytest.raises(DepositMismatch):
        c1_token_network_proxy.set_total_deposit(
            given_block_identifier="latest",
            channel_identifier=channel_identifier,
            total_deposit=1,
            partner=c2_client.address,
        )


def test_token_network_proxy(
    token_network_proxy, private_keys, token_proxy, chain_id, web3, contract_manager
):
    assert token_network_proxy.settlement_timeout_min() == TEST_SETTLE_TIMEOUT_MIN
    assert token_network_proxy.settlement_timeout_max() == TEST_SETTLE_TIMEOUT_MAX

    token_network_address = to_canonical_address(token_network_proxy.proxy.contract.address)

    c1_signer = LocalSigner(private_keys[1])
    c1_client = JSONRPCClient(web3, private_keys[1])
    c1_chain = BlockChainService(jsonrpc_client=c1_client, contract_manager=contract_manager)
    c2_client = JSONRPCClient(web3, private_keys[2])
    c1_token_network_proxy = TokenNetwork(
        jsonrpc_client=c1_client,
        token_network_address=token_network_address,
        contract_manager=contract_manager,
    )
    c2_token_network_proxy = TokenNetwork(
        jsonrpc_client=c2_client,
        token_network_address=token_network_address,
        contract_manager=contract_manager,
    )

    initial_token_balance = 100
    token_proxy.transfer(c1_client.address, initial_token_balance)
    token_proxy.transfer(c2_client.address, initial_token_balance)

    initial_balance_c1 = token_proxy.balance_of(c1_client.address)
    assert initial_balance_c1 == initial_token_balance
    initial_balance_c2 = token_proxy.balance_of(c2_client.address)
    assert initial_balance_c2 == initial_token_balance

    # instantiating a new channel - test basic assumptions
    assert (
        c1_token_network_proxy._channel_exists_and_not_settled(
            participant1=c1_client.address,
            participant2=c2_client.address,
            block_identifier="latest",
        )
        is False
    )

    channel_identifier = c1_token_network_proxy._call_and_check_result(
        "latest",
        "getChannelIdentifier",
        to_checksum_address(c1_client.address),
        to_checksum_address(c2_client.address),
    )
    assert channel_identifier == 0

    msg = "Zero is not a valid channel_identifier identifier, ValueError must be " "raised."
    with pytest.raises(ValueError, message=msg):
        assert c1_token_network_proxy.channel_is_opened(
            participant1=c1_client.address,
            participant2=c2_client.address,
            block_identifier="latest",
            channel_identifier=0,
        )

    msg = "Zero is not a valid channel_identifier identifier. ValueError must be " "raised."
    with pytest.raises(ValueError, message=msg):
        assert c1_token_network_proxy.channel_is_closed(
            participant1=c1_client.address,
            participant2=c2_client.address,
            block_identifier="latest",
            channel_identifier=0,
        )

    msg = (
        "Opening a channel with a settle_timeout lower then token "
        "network's minimum will fail. This must be validated and the "
        "transaction must not be sent."
    )
    with pytest.raises(InvalidSettleTimeout, message=msg):
        c1_token_network_proxy.new_netting_channel(
            partner=c2_client.address,
            settle_timeout=TEST_SETTLE_TIMEOUT_MIN - 1,
            given_block_identifier="latest",
        )

    msg = (
        "Opening a channel with a settle_timeout larger then token "
        "network's maximum will fail. This must be validated and the "
        "transaction must not be sent."
    )
    with pytest.raises(InvalidSettleTimeout, message=msg):
        c1_token_network_proxy.new_netting_channel(
            partner=c2_client.address,
            settle_timeout=TEST_SETTLE_TIMEOUT_MAX + 1,
            given_block_identifier="latest",
        )

    msg = (
        "Opening a channel with itself is not allow. This must be validated and "
        "the transaction must not be sent."
    )
    with pytest.raises(SamePeerAddress, message=msg):
        c1_token_network_proxy.new_netting_channel(
            partner=c1_client.address,
            settle_timeout=TEST_SETTLE_TIMEOUT_MIN,
            given_block_identifier="latest",
        )

    msg = "Trying a deposit to an inexisting channel must fail."
    with pytest.raises(RaidenUnrecoverableError, message=msg, match="does not exist"):
        c1_token_network_proxy.set_total_deposit(
            given_block_identifier="latest",
            channel_identifier=1,
            total_deposit=1,
            partner=c2_client.address,
        )

    msg = "Trying to close an inexisting channel must fail."
    match = "The channel was not open at the provided block"
    with pytest.raises(RaidenUnrecoverableError, message=msg, match=match):
        c1_token_network_proxy.close(
            channel_identifier=1,
            partner=c2_client.address,
            balance_hash=EMPTY_HASH,
            nonce=0,
            additional_hash=EMPTY_HASH,
            signature=EMPTY_SIGNATURE,
            given_block_identifier="latest",
        )

    channel_identifier = c1_token_network_proxy.new_netting_channel(
        partner=c2_client.address,
        settle_timeout=TEST_SETTLE_TIMEOUT_MIN,
        given_block_identifier="latest",
    )
    msg = "new_netting_channel did not return a valid channel id"
    assert isinstance(channel_identifier, T_ChannelID), msg

    msg = "multiple channels with the same peer are not allowed"
    with pytest.raises(DuplicatedChannelError, message=msg):
        c1_token_network_proxy.new_netting_channel(
            partner=c2_client.address,
            settle_timeout=TEST_SETTLE_TIMEOUT_MIN,
            given_block_identifier="latest",
        )

    assert (
        c1_token_network_proxy._channel_exists_and_not_settled(
            participant1=c1_client.address,
            participant2=c2_client.address,
            channel_identifier=channel_identifier,
            block_identifier="latest",
        )
        is True
    )

    assert (
        c1_token_network_proxy.channel_is_opened(
            participant1=c1_client.address,
            participant2=c2_client.address,
            block_identifier="latest",
            channel_identifier=channel_identifier,
        )
        is True
    )

    msg = "set_total_deposit must fail if the amount exceed the account's balance"
    with pytest.raises(DepositMismatch, message=msg):
        c1_token_network_proxy.set_total_deposit(
            given_block_identifier="latest",
            channel_identifier=channel_identifier,
            total_deposit=initial_token_balance + 1,
            partner=c2_client.address,
        )

    msg = "set_total_deposit must fail with a negative amount"
    with pytest.raises(DepositMismatch):
        c1_token_network_proxy.set_total_deposit(
            given_block_identifier="latest",
            channel_identifier=channel_identifier,
            total_deposit=-1,
            partner=c2_client.address,
        )

    msg = "set_total_deposit must fail with a zero amount"
    with pytest.raises(DepositMismatch):
        c1_token_network_proxy.set_total_deposit(
            given_block_identifier="latest",
            channel_identifier=channel_identifier,
            total_deposit=0,
            partner=c2_client.address,
        )

    c1_token_network_proxy.set_total_deposit(
        given_block_identifier="latest",
        channel_identifier=channel_identifier,
        total_deposit=10,
        partner=c2_client.address,
    )

    transferred_amount = 3
    balance_proof = BalanceProof(
        channel_identifier=channel_identifier,
        token_network_address=to_checksum_address(token_network_address),
        nonce=1,
        chain_id=chain_id,
        transferred_amount=transferred_amount,
    )
    signature = c1_signer.sign(data=balance_proof.serialize_bin())
    balance_proof.signature = encode_hex(signature)

    signature_number = int.from_bytes(signature, "big")
    bit_to_change = random.randint(0, SIGNATURE_SIZE_IN_BITS - 1)
    signature_number_bit_flipped = signature_number ^ (2 ** bit_to_change)

    invalid_signatures = [
        EMPTY_SIGNATURE,
        b"\x11" * 65,
        signature_number_bit_flipped.to_bytes(len(signature), "big"),
    ]

    msg = "close must fail if the signature is invalid"
    for invalid_signature in invalid_signatures:
        with pytest.raises(RaidenUnrecoverableError, message=msg):
            c2_token_network_proxy.close(
                channel_identifier=channel_identifier,
                partner=c1_client.address,
                balance_hash=decode_hex(balance_proof.balance_hash),
                nonce=balance_proof.nonce,
                additional_hash=decode_hex(balance_proof.additional_hash),
                signature=invalid_signature,
                given_block_identifier="latest",
            )

    blocknumber_prior_to_close = c2_client.block_number()

    c2_token_network_proxy.close(
        channel_identifier=channel_identifier,
        partner=c1_client.address,
        balance_hash=decode_hex(balance_proof.balance_hash),
        nonce=balance_proof.nonce,
        additional_hash=decode_hex(balance_proof.additional_hash),
        signature=decode_hex(balance_proof.signature),
        given_block_identifier="latest",
    )
    assert (
        c1_token_network_proxy.channel_is_closed(
            participant1=c1_client.address,
            participant2=c2_client.address,
            block_identifier="latest",
            channel_identifier=channel_identifier,
        )
        is True
    )
    assert (
        c1_token_network_proxy._channel_exists_and_not_settled(
            participant1=c1_client.address,
            participant2=c2_client.address,
            channel_identifier=channel_identifier,
            block_identifier="latest",
        )
        is True
    )

    msg = (
        "given_block_identifier is the block at which the transaction is being  "
        "sent. If the channel is already closed at that block the client code  "
        "has a programming error. An exception is raised for that."
    )
    with pytest.raises(RaidenUnrecoverableError, message=msg):
        c2_token_network_proxy.close(
            channel_identifier=channel_identifier,
            partner=c1_client.address,
            balance_hash=decode_hex(balance_proof.balance_hash),
            nonce=balance_proof.nonce,
            additional_hash=decode_hex(balance_proof.additional_hash),
            signature=decode_hex(balance_proof.signature),
            given_block_identifier="latest",
        )

    msg = (
        "The channel cannot be closed two times. If it was not closed at "
        "given_block_identifier but it is closed at the time the proxy is "
        "called an exception must be raised."
    )
    with pytest.raises(RaidenRecoverableError, message=msg):
        c2_token_network_proxy.close(
            channel_identifier=channel_identifier,
            partner=c1_client.address,
            balance_hash=decode_hex(balance_proof.balance_hash),
            nonce=balance_proof.nonce,
            additional_hash=decode_hex(balance_proof.additional_hash),
            signature=decode_hex(balance_proof.signature),
            given_block_identifier=blocknumber_prior_to_close,
        )

    msg = "depositing to a closed channel must fail"
    match = "setTotalDeposit call will fail. Channel is already closed"
    with pytest.raises(RaidenRecoverableError, message=msg, match=match):
        c2_token_network_proxy.set_total_deposit(
            given_block_identifier=blocknumber_prior_to_close,
            channel_identifier=channel_identifier,
            total_deposit=20,
            partner=c1_client.address,
        )

    c1_chain.wait_until_block(
        target_block_number=c1_chain.block_number() + TEST_SETTLE_TIMEOUT_MIN
    )

    invalid_transferred_amount = 1
    msg = "settle with invalid transferred_amount data must fail"
    with pytest.raises(RaidenUnrecoverableError, message=msg):
        c2_token_network_proxy.settle(
            channel_identifier=channel_identifier,
            transferred_amount=invalid_transferred_amount,
            locked_amount=0,
            locksroot=EMPTY_HASH,
            partner=c1_client.address,
            partner_transferred_amount=transferred_amount,
            partner_locked_amount=0,
            partner_locksroot=EMPTY_HASH,
            given_block_identifier="latest",
        )

    c2_token_network_proxy.settle(
        channel_identifier=channel_identifier,
        transferred_amount=0,
        locked_amount=0,
        locksroot=EMPTY_HASH,
        partner=c1_client.address,
        partner_transferred_amount=transferred_amount,
        partner_locked_amount=0,
        partner_locksroot=EMPTY_HASH,
        given_block_identifier="latest",
    )
    assert (
        c1_token_network_proxy._channel_exists_and_not_settled(
            participant1=c1_client.address,
            participant2=c2_client.address,
            channel_identifier=channel_identifier,
            block_identifier="latest",
        )
        is False
    )
    assert token_proxy.balance_of(c1_client.address) == (initial_balance_c1 - transferred_amount)
    assert token_proxy.balance_of(c2_client.address) == (initial_balance_c2 + transferred_amount)

    msg = "depositing to a settled channel must fail"
    match = "setTotalDeposit call will fail."
    with pytest.raises(RaidenUnrecoverableError, message=msg, match=match):
        c1_token_network_proxy.set_total_deposit(
            given_block_identifier="latest",
            channel_identifier=channel_identifier,
            total_deposit=10,
            partner=c2_client.address,
        )


def test_token_network_proxy_update_transfer(
    token_network_proxy, private_keys, token_proxy, chain_id, web3, contract_manager
):
    """Tests channel lifecycle, with `update_transfer` before settling"""
    token_network_address = to_canonical_address(token_network_proxy.proxy.contract.address)

    c1_client = JSONRPCClient(web3, private_keys[1])
    c1_chain = BlockChainService(jsonrpc_client=c1_client, contract_manager=contract_manager)
    c2_client = JSONRPCClient(web3, private_keys[2])
    c1_token_network_proxy = TokenNetwork(
        jsonrpc_client=c1_client,
        token_network_address=token_network_address,
        contract_manager=contract_manager,
    )
    c2_token_network_proxy = TokenNetwork(
        jsonrpc_client=c2_client,
        token_network_address=token_network_address,
        contract_manager=contract_manager,
    )
    # create a channel
    channel_identifier = c1_token_network_proxy.new_netting_channel(
        partner=c2_client.address, settle_timeout=10, given_block_identifier="latest"
    )
    # deposit to the channel
    initial_balance = 100
    token_proxy.transfer(c1_client.address, initial_balance)
    token_proxy.transfer(c2_client.address, initial_balance)
    initial_balance_c1 = token_proxy.balance_of(c1_client.address)
    assert initial_balance_c1 == initial_balance
    initial_balance_c2 = token_proxy.balance_of(c2_client.address)
    assert initial_balance_c2 == initial_balance
    c1_token_network_proxy.set_total_deposit(
        given_block_identifier="latest",
        channel_identifier=channel_identifier,
        total_deposit=10,
        partner=c2_client.address,
    )
    c2_token_network_proxy.set_total_deposit(
        given_block_identifier="latest",
        channel_identifier=channel_identifier,
        total_deposit=10,
        partner=c1_client.address,
    )
    # balance proof signed by c1
    transferred_amount_c1 = 1
    transferred_amount_c2 = 3
    balance_proof_c1 = BalanceProof(
        channel_identifier=channel_identifier,
        token_network_address=to_checksum_address(token_network_address),
        nonce=1,
        chain_id=chain_id,
        transferred_amount=transferred_amount_c1,
    )
    balance_proof_c1.signature = encode_hex(
        LocalSigner(private_keys[1]).sign(data=balance_proof_c1.serialize_bin())
    )
    # balance proof signed by c2
    balance_proof_c2 = BalanceProof(
        channel_identifier=channel_identifier,
        token_network_address=to_checksum_address(token_network_address),
        nonce=2,
        chain_id=chain_id,
        transferred_amount=transferred_amount_c2,
    )
    balance_proof_c2.signature = encode_hex(
        LocalSigner(private_keys[2]).sign(data=balance_proof_c2.serialize_bin())
    )

    non_closing_data = balance_proof_c1.serialize_bin(
        msg_type=MessageTypeId.BALANCE_PROOF_UPDATE
    ) + decode_hex(balance_proof_c1.signature)
    non_closing_signature = LocalSigner(c2_client.privkey).sign(data=non_closing_data)

    with pytest.raises(RaidenUnrecoverableError) as exc:
        c2_token_network_proxy.update_transfer(
            channel_identifier=channel_identifier,
            partner=c1_client.address,
            balance_hash=decode_hex(balance_proof_c1.balance_hash),
            nonce=balance_proof_c1.nonce,
            additional_hash=decode_hex(balance_proof_c1.additional_hash),
            closing_signature=decode_hex(balance_proof_c1.signature),
            non_closing_signature=non_closing_signature,
            given_block_identifier="latest",
        )

        assert "not in a closed state" in str(exc)

    # close by c1
    c1_token_network_proxy.close(
        channel_identifier=channel_identifier,
        partner=c2_client.address,
        balance_hash=decode_hex(balance_proof_c2.balance_hash),
        nonce=balance_proof_c2.nonce,
        additional_hash=decode_hex(balance_proof_c2.additional_hash),
        signature=decode_hex(balance_proof_c2.signature),
        given_block_identifier="latest",
    )

    # update transfer with completely invalid closing signature
    with pytest.raises(RaidenUnrecoverableError) as excinfo:
        c2_token_network_proxy.update_transfer(
            channel_identifier=channel_identifier,
            partner=c1_client.address,
            balance_hash=decode_hex(balance_proof_c1.balance_hash),
            nonce=balance_proof_c1.nonce,
            additional_hash=decode_hex(balance_proof_c1.additional_hash),
            closing_signature=b"",
            non_closing_signature=b"",
            given_block_identifier="latest",
        )
    assert str(excinfo.value) == "Couldn't verify the balance proof signature"

    # using invalid non-closing signature
    # Usual mistake when calling update Transfer - balance proof signature is missing in the data
    non_closing_data = balance_proof_c1.serialize_bin(msg_type=MessageTypeId.BALANCE_PROOF_UPDATE)
    non_closing_signature = LocalSigner(c2_client.privkey).sign(data=non_closing_data)
    with pytest.raises(RaidenUnrecoverableError):
        c2_token_network_proxy.update_transfer(
            channel_identifier=channel_identifier,
            partner=c1_client.address,
            balance_hash=decode_hex(balance_proof_c1.balance_hash),
            nonce=balance_proof_c1.nonce,
            additional_hash=decode_hex(balance_proof_c1.additional_hash),
            closing_signature=decode_hex(balance_proof_c1.signature),
            non_closing_signature=non_closing_signature,
            given_block_identifier="latest",
        )

    non_closing_data = balance_proof_c1.serialize_bin(
        msg_type=MessageTypeId.BALANCE_PROOF_UPDATE
    ) + decode_hex(balance_proof_c1.signature)
    non_closing_signature = LocalSigner(c2_client.privkey).sign(data=non_closing_data)
    c2_token_network_proxy.update_transfer(
        channel_identifier=channel_identifier,
        partner=c1_client.address,
        balance_hash=decode_hex(balance_proof_c1.balance_hash),
        nonce=balance_proof_c1.nonce,
        additional_hash=decode_hex(balance_proof_c1.additional_hash),
        closing_signature=decode_hex(balance_proof_c1.signature),
        non_closing_signature=non_closing_signature,
        given_block_identifier="latest",
    )

    with pytest.raises(RaidenUnrecoverableError) as exc:
        c1_token_network_proxy.settle(
            channel_identifier=channel_identifier,
            transferred_amount=transferred_amount_c1,
            locked_amount=0,
            locksroot=EMPTY_HASH,
            partner=c2_client.address,
            partner_transferred_amount=transferred_amount_c2,
            partner_locked_amount=0,
            partner_locksroot=EMPTY_HASH,
            given_block_identifier="latest",
        )

        assert "cannot be settled before settlement window is over" in str(exc)

    c1_chain.wait_until_block(target_block_number=c1_chain.block_number() + 10)

    # settling with an invalid amount
    with pytest.raises(RaidenUnrecoverableError):
        c1_token_network_proxy.settle(
            channel_identifier=channel_identifier,
            transferred_amount=2,
            locked_amount=0,
            locksroot=EMPTY_HASH,
            partner=c2_client.address,
            partner_transferred_amount=2,
            partner_locked_amount=0,
            partner_locksroot=EMPTY_HASH,
            given_block_identifier="latest",
        )

    # proper settle
    c1_token_network_proxy.settle(
        channel_identifier=channel_identifier,
        transferred_amount=transferred_amount_c1,
        locked_amount=0,
        locksroot=EMPTY_HASH,
        partner=c2_client.address,
        partner_transferred_amount=transferred_amount_c2,
        partner_locked_amount=0,
        partner_locksroot=EMPTY_HASH,
        given_block_identifier="latest",
    )
    assert token_proxy.balance_of(c2_client.address) == (
        initial_balance_c2 + transferred_amount_c1 - transferred_amount_c2
    )
    assert token_proxy.balance_of(c1_client.address) == (
        initial_balance_c1 + transferred_amount_c2 - transferred_amount_c1
    )

    # Already settled
    with pytest.raises(RaidenUnrecoverableError) as exc:
        c2_token_network_proxy.set_total_deposit(
            given_block_identifier="latest",
            channel_identifier=channel_identifier,
            total_deposit=20,
            partner=c1_client.address,
        )

        assert "getChannelIdentifier returned 0" in str(exc)


def test_query_pruned_state(token_network_proxy, private_keys, web3, contract_manager):
    """A test for https://github.com/raiden-network/raiden/issues/3566

    If pruning limit blocks pass make sure that can_query_state_for_block returns False.
    """

    token_network_address = to_canonical_address(token_network_proxy.proxy.contract.address)
    c1_client = JSONRPCClient(web3, private_keys[1])
    c1_chain = BlockChainService(jsonrpc_client=c1_client, contract_manager=contract_manager)
    c2_client = JSONRPCClient(web3, private_keys[2])
    c1_token_network_proxy = TokenNetwork(
        jsonrpc_client=c1_client,
        token_network_address=token_network_address,
        contract_manager=contract_manager,
    )
    # create a channel and query the state at the current block hash
    channel_identifier = c1_token_network_proxy.new_netting_channel(
        partner=c2_client.address, settle_timeout=10, given_block_identifier="latest"
    )
    block = c1_client.web3.eth.getBlock("latest")
    block_number = int(block["number"])
    block_hash = bytes(block["hash"])
    channel_id = c1_token_network_proxy.get_channel_identifier(
        participant1=c1_client.address, participant2=c2_client.address, block_identifier=block_hash
    )
    assert channel_id == channel_identifier
    assert c1_client.can_query_state_for_block(block_hash)

    # wait until state pruning kicks in
    target_block = block_number + STATE_PRUNING_AFTER_BLOCKS + 1
    c1_chain.wait_until_block(target_block_number=target_block)

    # and now query again for the old block identifier and see we can't query
    assert not c1_client.can_query_state_for_block(block_hash)


def test_token_network_actions_at_pruned_blocks(
    token_network_proxy, private_keys, token_proxy, web3, chain_id, contract_manager
):
    token_network_address = to_canonical_address(token_network_proxy.proxy.contract.address)
    c1_client = JSONRPCClient(web3, private_keys[1])
    c1_token_network_proxy = TokenNetwork(
        jsonrpc_client=c1_client,
        token_network_address=token_network_address,
        contract_manager=contract_manager,
    )
    c1_chain = BlockChainService(jsonrpc_client=c1_client, contract_manager=contract_manager)
    c2_client = JSONRPCClient(web3, private_keys[2])
    c3_client = JSONRPCClient(web3, private_keys[0])
    c2_token_network_proxy = TokenNetwork(
        jsonrpc_client=c2_client,
        token_network_address=token_network_address,
        contract_manager=contract_manager,
    )
    initial_token_balance = 100
    token_proxy.transfer(c1_client.address, initial_token_balance)
    token_proxy.transfer(c2_client.address, initial_token_balance)
    initial_balance_c1 = token_proxy.balance_of(c1_client.address)
    assert initial_balance_c1 == initial_token_balance
    initial_balance_c2 = token_proxy.balance_of(c2_client.address)
    assert initial_balance_c2 == initial_token_balance
    # create a channel
    settle_timeout = STATE_PRUNING_AFTER_BLOCKS + 10
    channel_identifier = c1_token_network_proxy.new_netting_channel(
        partner=c2_client.address, settle_timeout=settle_timeout, given_block_identifier="latest"
    )

    # Now wait until this block becomes pruned
    pruned_number = c1_chain.block_number()
    c1_chain.wait_until_block(target_block_number=pruned_number + STATE_PRUNING_AFTER_BLOCKS)

    # create a channel with given block being pruned, should always throw
    with pytest.raises(NoStateForBlockIdentifier):
        channel_identifier = c1_token_network_proxy.new_netting_channel(
            partner=c3_client.address, settle_timeout=10, given_block_identifier=pruned_number
        )

    # deposit with given block being pruned
    c1_token_network_proxy.set_total_deposit(
        given_block_identifier=pruned_number,
        channel_identifier=channel_identifier,
        total_deposit=2,
        partner=c2_client.address,
    )

    # balance proof signed by c1
    transferred_amount_c1 = 1
    balance_proof_c1 = BalanceProof(
        channel_identifier=channel_identifier,
        token_network_address=to_checksum_address(token_network_address),
        nonce=1,
        chain_id=chain_id,
        transferred_amount=transferred_amount_c1,
    )
    balance_proof_c1.signature = encode_hex(
        LocalSigner(private_keys[1]).sign(data=balance_proof_c1.serialize_bin())
    )
    non_closing_data = balance_proof_c1.serialize_bin(
        msg_type=MessageTypeId.BALANCE_PROOF_UPDATE
    ) + decode_hex(balance_proof_c1.signature)
    non_closing_signature = LocalSigner(c2_client.privkey).sign(data=non_closing_data)

    # close channel with given block being pruned
    c1_token_network_proxy.close(
        channel_identifier=channel_identifier,
        partner=c2_client.address,
        balance_hash=EMPTY_HASH,
        nonce=0,
        additional_hash=EMPTY_HASH,
        signature=EMPTY_SIGNATURE,
        given_block_identifier=pruned_number,
    )
    close_pruned_number = c1_chain.block_number()

    assert (
        c1_token_network_proxy.channel_is_closed(
            participant1=c1_client.address,
            participant2=c2_client.address,
            block_identifier="latest",
            channel_identifier=channel_identifier,
        )
        is True
    )
    assert (
        c1_token_network_proxy._channel_exists_and_not_settled(
            participant1=c1_client.address,
            participant2=c2_client.address,
            channel_identifier=channel_identifier,
            block_identifier="latest",
        )
        is True
    )

    c1_chain.wait_until_block(target_block_number=close_pruned_number + STATE_PRUNING_AFTER_BLOCKS)

    # update transfer with given block being pruned
    c2_token_network_proxy.update_transfer(
        channel_identifier=channel_identifier,
        partner=c1_client.address,
        balance_hash=decode_hex(balance_proof_c1.balance_hash),
        nonce=balance_proof_c1.nonce,
        additional_hash=decode_hex(balance_proof_c1.additional_hash),
        closing_signature=decode_hex(balance_proof_c1.signature),
        non_closing_signature=non_closing_signature,
        given_block_identifier=close_pruned_number,
    )

    # update transfer
    c1_chain.wait_until_block(target_block_number=c1_chain.block_number() + settle_timeout)

    # settle with given block being pruned
    c1_token_network_proxy.settle(
        channel_identifier=channel_identifier,
        transferred_amount=transferred_amount_c1,
        locked_amount=0,
        locksroot=EMPTY_HASH,
        partner=c2_client.address,
        partner_transferred_amount=0,
        partner_locked_amount=0,
        partner_locksroot=EMPTY_HASH,
        given_block_identifier=close_pruned_number,
    )
    assert token_proxy.balance_of(c2_client.address) == (
        initial_balance_c2 + transferred_amount_c1 - 0
    )
    assert token_proxy.balance_of(c1_client.address) == (
        initial_balance_c1 + 0 - transferred_amount_c1
    )
