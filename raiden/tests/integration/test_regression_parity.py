import math
from typing import cast
from unittest.mock import Mock, patch

import pytest

from raiden import waiting
from raiden.constants import BLOCK_ID_LATEST
from raiden.exceptions import InvalidSecret
from raiden.network.rpc.client import JSONRPCClient
from raiden.raiden_service import RaidenService
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.integration.fixtures.raiden_network import RestartNode
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import wait_for_state_change
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract
from raiden.tests.utils.transfer import TransferState, get_channelstate, transfer
from raiden.transfer import views
from raiden.transfer.architecture import BalanceProofSignedState
from raiden.transfer.state_change import ContractReceiveChannelSettled
from raiden.utils.packing import pack_signed_balance_proof
from raiden.utils.typing import BlockNumber, List, PaymentAmount, PaymentID, TokenAddress
from raiden_contracts.constants import MessageTypeId

pytestmark = pytest.mark.usefixtures("skip_if_not_parity")

# At least the confirmed block must be kept around, the additional blocks is to
# given some room for the test to execute
pruning_history = DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 5

# set very low values to force the client to prune old state
STATE_PRUNING = {
    "pruning": "fast",
    "pruning-history": pruning_history,
    "pruning-memory": 1,
    "cache-size-db": 1,
    "cache-size-blocks": 1,
    "cache-size-queue": 1,
    "cache-size": 1,
}


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("blockchain_extra_config", [STATE_PRUNING])
@patch("raiden.message_handler.decrypt_secret", side_effect=InvalidSecret)
def test_locksroot_loading_during_channel_settle_handling(  # pylint: disable=unused-argument
    decrypt_patch: Mock,
    raiden_chain: List[RaidenService],
    restart_node: RestartNode,
    deploy_client: JSONRPCClient,
    token_addresses: List[TokenAddress],
) -> None:
    app0, app1 = raiden_chain
    token_network_registry_address = app0.default_registry.address
    token_address = token_addresses[0]

    transfer(
        initiator_app=app0,
        target_app=app1,
        token_address=token_address,
        amount=PaymentAmount(10),
        identifier=PaymentID(1),
        transfer_state=TransferState.SECRET_NOT_REQUESTED,
        routes=[[app0, app1]],
    )
    transfer(
        initiator_app=app1,
        target_app=app0,
        token_address=token_address,
        amount=PaymentAmount(7),
        identifier=PaymentID(2),
        transfer_state=TransferState.SECRET_NOT_REQUESTED,
        routes=[[app1, app0]],
    )

    token_network_address = views.get_token_network_address_by_token_address(
        chain_state=views.state_from_raiden(app0),
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )
    assert token_network_address
    channel_state = get_channelstate(
        app0=app0, app1=app1, token_network_address=token_network_address
    )

    channel = app0.proxy_manager.payment_channel(
        channel_state=channel_state, block_identifier=BLOCK_ID_LATEST
    )
    balance_proof = channel_state.partner_state.balance_proof
    assert balance_proof
    balance_proof = cast(BalanceProofSignedState, balance_proof)
    block_number = app0.rpc_client.block_number()

    closing_data = pack_signed_balance_proof(
        msg_type=MessageTypeId.BALANCE_PROOF,
        nonce=balance_proof.nonce,
        balance_hash=balance_proof.balance_hash,
        additional_hash=balance_proof.message_hash,
        canonical_identifier=balance_proof.canonical_identifier,
        partner_signature=balance_proof.signature,
    )
    closing_signature = app0.signer.sign(data=closing_data)

    channel.close(
        nonce=balance_proof.nonce,
        balance_hash=balance_proof.balance_hash,
        additional_hash=balance_proof.message_hash,
        non_closing_signature=balance_proof.signature,
        closing_signature=closing_signature,
        block_identifier=block_number,
    )

    close_block = app0.rpc_client.block_number()

    app0.stop()

    waiting.wait_for_settle(
        raiden=app1,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
        channel_ids=[channel_state.canonical_identifier.channel_identifier],
        retry_timeout=1,
    )

    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcWithStorageTest")
    iterations = 1000

    def send_transaction() -> None:
        estimated_transaction = deploy_client.estimate_gas(
            contract_proxy, "waste_storage", {}, iterations
        )
        assert estimated_transaction
        transaction = deploy_client.transact(estimated_transaction)
        deploy_client.poll_transaction(transaction)

    for _ in range(10):
        send_transaction()

    # Wait until the target block has be prunned, it has to be larger than
    # pruning_history
    pruned_after_blocks = math.ceil(pruning_history * 1.5)
    pruned_block = BlockNumber(close_block + pruned_after_blocks)

    waiting.wait_for_block(raiden=app1, block_number=pruned_block, retry_timeout=1)

    channel = app0.proxy_manager.payment_channel(channel_state, BLOCK_ID_LATEST)

    # make sure the block was pruned
    with pytest.raises(ValueError):
        channel.detail(block_identifier=close_block)

    # This must not raise when the settle event is being raised and the
    # locksroot is being recover (#3856)
    restart_node(app0)

    assert wait_for_state_change(
        raiden=app0,
        item_type=ContractReceiveChannelSettled,
        attributes={"canonical_identifier": channel_state.canonical_identifier},
        retry_timeout=1,
    )
