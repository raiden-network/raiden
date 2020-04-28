import pytest
from web3 import Web3

from raiden.blockchain.events import get_all_netting_channel_events
from raiden.constants import (
    BLOCK_ID_LATEST,
    EMPTY_BALANCE_HASH,
    EMPTY_MESSAGE_HASH,
    EMPTY_SIGNATURE,
    GENESIS_BLOCK_NUMBER,
    LOCKSROOT_OF_NO_LOCKS,
)
from raiden.exceptions import (
    BrokenPreconditionError,
    RaidenRecoverableError,
    RaidenUnrecoverableError,
)
from raiden.network.proxies.proxy_manager import ProxyManager, ProxyManagerMetadata
from raiden.network.proxies.token import Token
from raiden.network.proxies.token_network import TokenNetwork
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.integration.network.proxies import BalanceProof
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.transfer.state import (
    NettingChannelEndState,
    NettingChannelState,
    SuccessfulTransactionState,
)
from raiden.utils.keys import privatekey_to_address
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import (
    Balance,
    BlockNumber,
    BlockTimeout,
    ChainID,
    List,
    LockedAmount,
    Nonce,
    PrivateKey,
    TokenAmount,
    TokenNetworkRegistryAddress,
)
from raiden_contracts.constants import TEST_SETTLE_TIMEOUT_MIN, MessageTypeId
from raiden_contracts.contract_manager import ContractManager


def test_payment_channel_proxy_basics(
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_network_proxy: TokenNetwork,
    token_proxy: Token,
    chain_id: ChainID,
    private_keys: List[PrivateKey],
    web3: Web3,
    contract_manager: ContractManager,
    reveal_timeout: BlockTimeout,
) -> None:
    token_network_address = token_network_proxy.address
    partner = privatekey_to_address(private_keys[0])

    rpc_client = JSONRPCClient(web3, private_keys[1])
    proxy_manager = ProxyManager(
        rpc_client=rpc_client,
        contract_manager=contract_manager,
        metadata=ProxyManagerMetadata(
            token_network_registry_deployed_at=GENESIS_BLOCK_NUMBER,
            filters_start_at=GENESIS_BLOCK_NUMBER,
        ),
    )
    token_network_proxy = proxy_manager.token_network(
        address=token_network_address, block_identifier=BLOCK_ID_LATEST
    )
    start_block = web3.eth.blockNumber

    channel_identifier, _, _ = token_network_proxy.new_netting_channel(
        partner=partner,
        settle_timeout=TEST_SETTLE_TIMEOUT_MIN,
        given_block_identifier=BLOCK_ID_LATEST,
    )
    assert channel_identifier is not None

    channel_state = NettingChannelState(
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_id,
            token_network_address=token_network_address,
            channel_identifier=channel_identifier,
        ),
        token_address=token_network_proxy.token_address(),
        token_network_registry_address=token_network_registry_address,
        reveal_timeout=reveal_timeout,
        settle_timeout=BlockTimeout(TEST_SETTLE_TIMEOUT_MIN),
        fee_schedule=FeeScheduleState(),
        our_state=NettingChannelEndState(
            address=token_network_proxy.client.address, contract_balance=Balance(0)
        ),
        partner_state=NettingChannelEndState(address=partner, contract_balance=Balance(0)),
        open_transaction=SuccessfulTransactionState(finished_block_number=BlockNumber(0)),
    )
    channel_proxy_1 = proxy_manager.payment_channel(
        channel_state=channel_state, block_identifier=BLOCK_ID_LATEST
    )

    assert channel_proxy_1.channel_identifier == channel_identifier
    assert channel_proxy_1.opened(BLOCK_ID_LATEST) is True

    # Test deposit
    initial_token_balance = 100
    token_proxy.transfer(rpc_client.address, TokenAmount(initial_token_balance))
    assert token_proxy.balance_of(rpc_client.address) == initial_token_balance
    assert token_proxy.balance_of(partner) == 0
    channel_proxy_1.approve_and_set_total_deposit(
        total_deposit=TokenAmount(10), block_identifier=BLOCK_ID_LATEST
    )

    # ChannelOpened, ChannelNewDeposit
    channel_events = get_all_netting_channel_events(
        proxy_manager=proxy_manager,
        token_network_address=token_network_address,
        netting_channel_identifier=channel_proxy_1.channel_identifier,
        contract_manager=contract_manager,
        from_block=start_block,
        to_block=web3.eth.blockNumber,
    )

    assert len(channel_events) == 2

    block_before_close = web3.eth.blockNumber
    empty_balance_proof = BalanceProof(
        channel_identifier=channel_proxy_1.channel_identifier,
        token_network_address=token_network_address,
        balance_hash=EMPTY_BALANCE_HASH,
        nonce=0,
        chain_id=chain_id,
        transferred_amount=TokenAmount(0),
    )
    closing_data = (
        empty_balance_proof.serialize_bin(msg_type=MessageTypeId.BALANCE_PROOF) + EMPTY_SIGNATURE
    )
    channel_proxy_1.close(
        nonce=Nonce(0),
        balance_hash=EMPTY_BALANCE_HASH,
        additional_hash=EMPTY_MESSAGE_HASH,
        non_closing_signature=EMPTY_SIGNATURE,
        closing_signature=LocalSigner(private_keys[1]).sign(data=closing_data),
        block_identifier=BLOCK_ID_LATEST,
    )
    assert channel_proxy_1.closed(BLOCK_ID_LATEST) is True
    # ChannelOpened, ChannelNewDeposit, ChannelClosed
    channel_events = get_all_netting_channel_events(
        proxy_manager=proxy_manager,
        token_network_address=token_network_address,
        netting_channel_identifier=channel_proxy_1.channel_identifier,
        contract_manager=contract_manager,
        from_block=start_block,
        to_block=web3.eth.blockNumber,
    )
    assert len(channel_events) == 3

    # check the settlement timeouts again
    assert channel_proxy_1.settle_timeout() == TEST_SETTLE_TIMEOUT_MIN

    # update transfer -- we need to wait on +1 since we use the latest block on parity for
    # estimate gas and at the time the latest block is the settle timeout block.
    # More info: https://github.com/raiden-network/raiden/pull/3699#discussion_r270477227
    rpc_client.wait_until_block(
        target_block_number=BlockNumber(rpc_client.block_number() + TEST_SETTLE_TIMEOUT_MIN + 1)
    )

    channel_proxy_1.settle(
        transferred_amount=TokenAmount(0),
        locked_amount=LockedAmount(0),
        locksroot=LOCKSROOT_OF_NO_LOCKS,
        partner_transferred_amount=TokenAmount(0),
        partner_locked_amount=LockedAmount(0),
        partner_locksroot=LOCKSROOT_OF_NO_LOCKS,
        block_identifier=BLOCK_ID_LATEST,
    )
    assert channel_proxy_1.settled(BLOCK_ID_LATEST) is True
    # ChannelOpened, ChannelNewDeposit, ChannelClosed, ChannelSettled
    channel_events = get_all_netting_channel_events(
        proxy_manager=proxy_manager,
        token_network_address=token_network_address,
        netting_channel_identifier=channel_proxy_1.channel_identifier,
        contract_manager=contract_manager,
        from_block=start_block,
        to_block=web3.eth.blockNumber,
    )
    assert len(channel_events) == 4

    new_channel_identifier, _, _ = token_network_proxy.new_netting_channel(
        partner=partner,
        settle_timeout=TEST_SETTLE_TIMEOUT_MIN,
        given_block_identifier=BLOCK_ID_LATEST,
    )
    assert new_channel_identifier is not None

    channel_state = NettingChannelState(
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_id,
            token_network_address=token_network_address,
            channel_identifier=new_channel_identifier,
        ),
        token_address=token_network_proxy.token_address(),
        token_network_registry_address=token_network_registry_address,
        reveal_timeout=reveal_timeout,
        settle_timeout=BlockTimeout(TEST_SETTLE_TIMEOUT_MIN),
        fee_schedule=FeeScheduleState(),
        our_state=NettingChannelEndState(
            address=token_network_proxy.client.address, contract_balance=Balance(0)
        ),
        partner_state=NettingChannelEndState(address=partner, contract_balance=Balance(0)),
        open_transaction=SuccessfulTransactionState(finished_block_number=BlockNumber(0)),
    )
    channel_proxy_2 = proxy_manager.payment_channel(
        channel_state=channel_state, block_identifier=BLOCK_ID_LATEST
    )

    assert channel_proxy_2.channel_identifier == new_channel_identifier
    assert channel_proxy_2.opened(BLOCK_ID_LATEST) is True

    msg = "The channel was already closed, the second call must fail"
    with pytest.raises(RaidenRecoverableError):
        channel_proxy_1.close(
            nonce=Nonce(0),
            balance_hash=EMPTY_BALANCE_HASH,
            additional_hash=EMPTY_MESSAGE_HASH,
            non_closing_signature=EMPTY_SIGNATURE,
            closing_signature=LocalSigner(private_keys[1]).sign(data=closing_data),
            block_identifier=block_before_close,
        )
        pytest.fail(msg)

    msg = "The channel is not open at latest, this must raise"
    with pytest.raises(RaidenUnrecoverableError):
        channel_proxy_1.close(
            nonce=Nonce(0),
            balance_hash=EMPTY_BALANCE_HASH,
            additional_hash=EMPTY_MESSAGE_HASH,
            non_closing_signature=EMPTY_SIGNATURE,
            closing_signature=LocalSigner(private_keys[1]).sign(data=closing_data),
            block_identifier=BLOCK_ID_LATEST,
        )
        pytest.fail(msg)

    msg = (
        "The channel was not opened at the provided block (latest). "
        "This call should never have been attempted."
    )
    with pytest.raises(BrokenPreconditionError):
        channel_proxy_1.approve_and_set_total_deposit(
            total_deposit=TokenAmount(20), block_identifier=BLOCK_ID_LATEST
        )
        pytest.fail(msg)
