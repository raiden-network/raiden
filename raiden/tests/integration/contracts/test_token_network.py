import pytest
from eth_utils import decode_hex, encode_hex, to_canonical_address, to_checksum_address

from raiden.constants import EMPTY_HASH
from raiden.exceptions import (
    DepositMismatch,
    DuplicatedChannelError,
    InvalidSettleTimeout,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
    SamePeerAddress,
)
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies import TokenNetwork
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.integration.contracts import BalanceProof
from raiden.utils.signer import LocalSigner
from raiden_contracts.constants import (
    TEST_SETTLE_TIMEOUT_MAX,
    TEST_SETTLE_TIMEOUT_MIN,
    MessageTypeId,
)


def test_token_network_deposit_race(
        token_network_proxy,
        private_keys,
        token_proxy,
        web3,
        contract_manager,
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
    token_proxy.transfer(c1_client.address, 10, 'latest')
    channel_identifier = c1_token_network_proxy.new_netting_channel(
        partner=c2_client.address,
        settle_timeout=TEST_SETTLE_TIMEOUT_MIN,
        given_block_identifier='latest',
    )
    assert channel_identifier is not None

    c1_token_network_proxy.set_total_deposit(
        given_block_identifier='latest',
        channel_identifier=channel_identifier,
        total_deposit=2,
        partner=c2_client.address,
    )
    with pytest.raises(DepositMismatch):
        c1_token_network_proxy.set_total_deposit(
            given_block_identifier='latest',
            channel_identifier=channel_identifier,
            total_deposit=1,
            partner=c2_client.address,
        )


def test_token_network_proxy_basics(
        token_network_proxy,
        private_keys,
        token_proxy,
        chain_id,
        web3,
        contract_manager,
        skip_if_parity,
):
    # check settlement timeouts
    assert token_network_proxy.settlement_timeout_min() == TEST_SETTLE_TIMEOUT_MIN
    assert token_network_proxy.settlement_timeout_max() == TEST_SETTLE_TIMEOUT_MAX

    token_network_address = to_canonical_address(token_network_proxy.proxy.contract.address)

    c1_client = JSONRPCClient(web3, private_keys[1])
    c1_chain = BlockChainService(
        jsonrpc_client=c1_client,
        contract_manager=contract_manager,
    )
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
    token_proxy.transfer(c1_client.address, initial_token_balance, 'latest')
    token_proxy.transfer(c2_client.address, initial_token_balance, 'latest')
    initial_balance_c1 = token_proxy.balance_of(c1_client.address)
    assert initial_balance_c1 == initial_token_balance
    initial_balance_c2 = token_proxy.balance_of(c2_client.address)
    assert initial_balance_c2 == initial_token_balance

    # instantiating a new channel - test basic assumptions
    assert c1_token_network_proxy.channel_exists_and_not_settled(
        participant1=c1_client.address,
        participant2=c2_client.address,
        block_identifier='latest',
    ) is False

    channel_identifier = c1_token_network_proxy._call_and_check_result(
        'latest',
        'getChannelIdentifier',
        to_checksum_address(c1_client.address),
        to_checksum_address(c2_client.address),
    )
    assert c1_token_network_proxy.channel_is_opened(
        participant1=c1_client.address,
        participant2=c2_client.address,
        block_identifier='latest',
        channel_identifier=channel_identifier,
    ) is False
    assert c1_token_network_proxy.channel_is_closed(
        participant1=c1_client.address,
        participant2=c2_client.address,
        block_identifier='latest',
        channel_identifier=channel_identifier,
    ) is False
    # test timeout limits
    with pytest.raises(InvalidSettleTimeout):
        c1_token_network_proxy.new_netting_channel(
            partner=c2_client.address,
            settle_timeout=TEST_SETTLE_TIMEOUT_MIN - 1,
            given_block_identifier='latest',
        )
    with pytest.raises(InvalidSettleTimeout):
        c1_token_network_proxy.new_netting_channel(
            partner=c2_client.address,
            settle_timeout=TEST_SETTLE_TIMEOUT_MAX + 1,
            given_block_identifier='latest',
        )
    # channel to self
    with pytest.raises(SamePeerAddress):
        c1_token_network_proxy.new_netting_channel(
            partner=c1_client.address,
            settle_timeout=TEST_SETTLE_TIMEOUT_MIN,
            given_block_identifier='latest',
        )

    # Channel is not open yet
    with pytest.raises(RaidenUnrecoverableError) as exc:
        c1_token_network_proxy.set_total_deposit(
            given_block_identifier='latest',
            channel_identifier=1,
            total_deposit=1,
            partner=c2_client.address,
        )

        assert 'does not exist' in str(exc)

    # Channel is not open yet
    with pytest.raises(RaidenUnrecoverableError) as exc:
        c1_token_network_proxy.close(
            channel_identifier=1,
            partner=c2_client.address,
            balance_hash=EMPTY_HASH,
            nonce=0,
            additional_hash=EMPTY_HASH,
            signature=EMPTY_HASH,
            given_block_identifier='latest',
        )

        assert 'does not exist' in str(exc)

    # actually create a channel
    channel_identifier = c1_token_network_proxy.new_netting_channel(
        partner=c2_client.address,
        settle_timeout=TEST_SETTLE_TIMEOUT_MIN,
        given_block_identifier='latest',
    )
    assert channel_identifier is not None
    # multiple channels with the same peer are not allowed
    with pytest.raises(DuplicatedChannelError):
        c1_token_network_proxy.new_netting_channel(
            partner=c2_client.address,
            settle_timeout=TEST_SETTLE_TIMEOUT_MIN,
            given_block_identifier='latest',
        )
    assert c1_token_network_proxy.channel_exists_and_not_settled(
        participant1=c1_client.address,
        participant2=c2_client.address,
        channel_identifier=channel_identifier,
        block_identifier='latest',
    ) is True
    assert c1_token_network_proxy.channel_is_opened(
        participant1=c1_client.address,
        participant2=c2_client.address,
        block_identifier='latest',
        channel_identifier=channel_identifier,
    ) is True

    # channel is open.
    # deposit with no balance
    with pytest.raises(DepositMismatch):
        c1_token_network_proxy.set_total_deposit(
            given_block_identifier='latest',
            channel_identifier=channel_identifier,
            total_deposit=101,
            partner=c2_client.address,
        )

    # no negative deposit
    with pytest.raises(DepositMismatch):
        c1_token_network_proxy.set_total_deposit(
            given_block_identifier='latest',
            channel_identifier=channel_identifier,
            total_deposit=-1,
            partner=c2_client.address,
        )
    # actual deposit
    c1_token_network_proxy.set_total_deposit(
        given_block_identifier='latest',
        channel_identifier=channel_identifier,
        total_deposit=10,
        partner=c2_client.address,
    )

    # balance proof by c2
    transferred_amount = 3
    balance_proof = BalanceProof(
        channel_identifier=channel_identifier,
        token_network_address=to_checksum_address(token_network_address),
        nonce=1,
        chain_id=chain_id,
        transferred_amount=transferred_amount,
    )
    balance_proof.signature = encode_hex(
        LocalSigner(private_keys[1]).sign(
            data=balance_proof.serialize_bin(),
        ),
    )
    # close with invalid signature
    with pytest.raises(RaidenUnrecoverableError):
        c2_token_network_proxy.close(
            channel_identifier=channel_identifier,
            partner=c1_client.address,
            balance_hash=decode_hex(balance_proof.balance_hash),
            nonce=balance_proof.nonce,
            additional_hash=decode_hex(balance_proof.additional_hash),
            signature=b'\x11' * 65,
            given_block_identifier='latest',
        )

    # correct close
    c2_token_network_proxy.close(
        channel_identifier=channel_identifier,
        partner=c1_client.address,
        balance_hash=decode_hex(balance_proof.balance_hash),
        nonce=balance_proof.nonce,
        additional_hash=decode_hex(balance_proof.additional_hash),
        signature=decode_hex(balance_proof.signature),
        given_block_identifier='latest',
    )
    assert c1_token_network_proxy.channel_is_closed(
        participant1=c1_client.address,
        participant2=c2_client.address,
        block_identifier='latest',
        channel_identifier=channel_identifier,
    ) is True
    assert c1_token_network_proxy.channel_exists_and_not_settled(
        participant1=c1_client.address,
        participant2=c2_client.address,
        channel_identifier=channel_identifier,
        block_identifier='latest',
    ) is True

    # closing already closed channel
    with pytest.raises(RaidenRecoverableError):
        c2_token_network_proxy.close(
            channel_identifier=channel_identifier,
            partner=c1_client.address,
            balance_hash=decode_hex(balance_proof.balance_hash),
            nonce=balance_proof.nonce,
            additional_hash=decode_hex(balance_proof.additional_hash),
            signature=decode_hex(balance_proof.signature),
            given_block_identifier='latest',
        )

    with pytest.raises(RaidenRecoverableError) as exc:
        c2_token_network_proxy.set_total_deposit(
            given_block_identifier='latest',
            channel_identifier=channel_identifier,
            total_deposit=20,
            partner=c1_client.address,
        )

        assert 'not in an open state' in str(exc)

    with pytest.raises(RaidenRecoverableError) as exc:
        c2_token_network_proxy.close(
            channel_identifier=channel_identifier,
            partner=c1_client.address,
            balance_hash=decode_hex(balance_proof.balance_hash),
            nonce=balance_proof.nonce,
            additional_hash=decode_hex(balance_proof.additional_hash),
            signature=decode_hex(balance_proof.signature),
            given_block_identifier='latest',
        )

        assert 'not in an open state' in str(exc)

    # update transfer
    c1_chain.wait_until_block(
        target_block_number=c1_chain.block_number() + TEST_SETTLE_TIMEOUT_MIN,
    )

    # try to settle using incorrect data
    with pytest.raises(RaidenUnrecoverableError):
        c2_token_network_proxy.settle(
            channel_identifier=channel_identifier,
            transferred_amount=1,
            locked_amount=0,
            locksroot=EMPTY_HASH,
            partner=c1_client.address,
            partner_transferred_amount=transferred_amount,
            partner_locked_amount=0,
            partner_locksroot=EMPTY_HASH,
            given_block_identifier='latest',
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
        given_block_identifier='latest',
    )
    assert c1_token_network_proxy.channel_exists_and_not_settled(
        participant1=c1_client.address,
        participant2=c2_client.address,
        channel_identifier=channel_identifier,
        block_identifier='latest',
    ) is False
    assert token_proxy.balance_of(c1_client.address) == (initial_balance_c1 - transferred_amount)
    assert token_proxy.balance_of(c2_client.address) == (initial_balance_c2 + transferred_amount)

    with pytest.raises(RaidenUnrecoverableError) as exc:
        c1_token_network_proxy.set_total_deposit(
            given_block_identifier='latest',
            channel_identifier=channel_identifier,
            total_deposit=10,
            partner=c2_client.address,
        )
        # No channel exists
        assert 'getChannelIdentifier returned 0' in str(exc)


def test_token_network_proxy_update_transfer(
        token_network_proxy,
        private_keys,
        token_proxy,
        chain_id,
        web3,
        contract_manager,
        skip_if_parity,
):
    """Tests channel lifecycle, with `update_transfer` before settling"""
    token_network_address = to_canonical_address(token_network_proxy.proxy.contract.address)

    c1_client = JSONRPCClient(web3, private_keys[1])
    c1_chain = BlockChainService(
        jsonrpc_client=c1_client,
        contract_manager=contract_manager,
    )
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
        partner=c2_client.address,
        settle_timeout=10,
        given_block_identifier='latest',
    )
    # deposit to the channel
    initial_balance = 100
    token_proxy.transfer(c1_client.address, initial_balance, 'latest')
    token_proxy.transfer(c2_client.address, initial_balance, 'latest')
    initial_balance_c1 = token_proxy.balance_of(c1_client.address)
    assert initial_balance_c1 == initial_balance
    initial_balance_c2 = token_proxy.balance_of(c2_client.address)
    assert initial_balance_c2 == initial_balance
    c1_token_network_proxy.set_total_deposit(
        given_block_identifier='latest',
        channel_identifier=channel_identifier,
        total_deposit=10,
        partner=c2_client.address,
    )
    c2_token_network_proxy.set_total_deposit(
        given_block_identifier='latest',
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
        LocalSigner(private_keys[1]).sign(
            data=balance_proof_c1.serialize_bin(),
        ),
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
        LocalSigner(private_keys[2]).sign(
            data=balance_proof_c2.serialize_bin(),
        ),
    )

    non_closing_data = balance_proof_c1.serialize_bin(
        msg_type=MessageTypeId.BALANCE_PROOF_UPDATE,
    ) + decode_hex(balance_proof_c1.signature)
    non_closing_signature = LocalSigner(c2_client.privkey).sign(
        data=non_closing_data,
    )

    with pytest.raises(RaidenUnrecoverableError) as exc:
        c2_token_network_proxy.update_transfer(
            channel_identifier=channel_identifier,
            partner=c1_client.address,
            balance_hash=decode_hex(balance_proof_c1.balance_hash),
            nonce=balance_proof_c1.nonce,
            additional_hash=decode_hex(balance_proof_c1.additional_hash),
            closing_signature=decode_hex(balance_proof_c1.signature),
            non_closing_signature=non_closing_signature,
            given_block_identifier='latest',
        )

        assert 'not in a closed state' in str(exc)

    # close by c1
    c1_token_network_proxy.close(
        channel_identifier=channel_identifier,
        partner=c2_client.address,
        balance_hash=decode_hex(balance_proof_c2.balance_hash),
        nonce=balance_proof_c2.nonce,
        additional_hash=decode_hex(balance_proof_c2.additional_hash),
        signature=decode_hex(balance_proof_c2.signature),
        given_block_identifier='latest',
    )

    # update transfer with completely invalid closing signature
    with pytest.raises(RaidenUnrecoverableError) as excinfo:
        c2_token_network_proxy.update_transfer(
            channel_identifier=channel_identifier,
            partner=c1_client.address,
            balance_hash=decode_hex(balance_proof_c1.balance_hash),
            nonce=balance_proof_c1.nonce,
            additional_hash=decode_hex(balance_proof_c1.additional_hash),
            closing_signature=b'',
            non_closing_signature=b'',
            given_block_identifier='latest',
        )
    assert str(excinfo.value) == "Couldn't verify the balance proof signature"

    # using invalid non-closing signature
    # Usual mistake when calling update Transfer - balance proof signature is missing in the data
    non_closing_data = balance_proof_c1.serialize_bin(msg_type=MessageTypeId.BALANCE_PROOF_UPDATE)
    non_closing_signature = LocalSigner(c2_client.privkey).sign(
        data=non_closing_data,
    )
    with pytest.raises(RaidenUnrecoverableError):
        c2_token_network_proxy.update_transfer(
            channel_identifier=channel_identifier,
            partner=c1_client.address,
            balance_hash=decode_hex(balance_proof_c1.balance_hash),
            nonce=balance_proof_c1.nonce,
            additional_hash=decode_hex(balance_proof_c1.additional_hash),
            closing_signature=decode_hex(balance_proof_c1.signature),
            non_closing_signature=non_closing_signature,
            given_block_identifier='latest',
        )

    non_closing_data = balance_proof_c1.serialize_bin(
        msg_type=MessageTypeId.BALANCE_PROOF_UPDATE,
    ) + decode_hex(balance_proof_c1.signature)
    non_closing_signature = LocalSigner(c2_client.privkey).sign(
        data=non_closing_data,
    )
    c2_token_network_proxy.update_transfer(
        channel_identifier=channel_identifier,
        partner=c1_client.address,
        balance_hash=decode_hex(balance_proof_c1.balance_hash),
        nonce=balance_proof_c1.nonce,
        additional_hash=decode_hex(balance_proof_c1.additional_hash),
        closing_signature=decode_hex(balance_proof_c1.signature),
        non_closing_signature=non_closing_signature,
        given_block_identifier='latest',
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
            given_block_identifier='latest',
        )

        assert 'cannot be settled before settlement window is over' in str(exc)

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
            given_block_identifier='latest',
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
        given_block_identifier='latest',
    )
    assert (token_proxy.balance_of(c2_client.address) ==
            (initial_balance_c2 + transferred_amount_c1 - transferred_amount_c2))
    assert (token_proxy.balance_of(c1_client.address) ==
            (initial_balance_c1 + transferred_amount_c2 - transferred_amount_c1))

    # Already settled
    with pytest.raises(RaidenUnrecoverableError) as exc:
        c2_token_network_proxy.set_total_deposit(
            given_block_identifier='latest',
            channel_identifier=channel_identifier,
            total_deposit=20,
            partner=c1_client.address,
        )

        assert 'getChannelIdentifier returned 0' in str(exc)
