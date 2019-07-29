import pytest

from raiden import waiting
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import wait_for_state_change
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract
from raiden.tests.utils.transfer import TransferState, get_channelstate, transfer
from raiden.transfer import views
from raiden.transfer.state_change import ContractReceiveChannelSettled
from raiden.utils import safe_gas_limit
from raiden.utils.packing import pack_signed_balance_proof

pytestmark = pytest.mark.usefixtures("skip_if_not_parity")

# set very low values to force the client to prune old state
STATE_PRUNING = {
    "pruning": "fast",
    "pruning-history": 1,
    "pruning-memory": 1,
    "cache-size-db": 1,
    "cache-size-blocks": 1,
    "cache-size-queue": 1,
    "cache-size": 1,
}


@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("blockchain_extra_config", [STATE_PRUNING])
def test_locksroot_loading_during_channel_settle_handling(
    raiden_chain, deploy_client, token_addresses
):
    raise_on_failure(
        raiden_chain,
        run_test_locksroot_loading_during_channel_settle_handling,
        raiden_chain=raiden_chain,
        deploy_client=deploy_client,
        token_addresses=token_addresses,
    )


def run_test_locksroot_loading_during_channel_settle_handling(
    raiden_chain, deploy_client, token_addresses
):
    app0, app1 = raiden_chain
    payment_network_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]

    transfer(
        initiator_app=app0,
        target_app=app1,
        token_address=token_address,
        amount=10,
        identifier=1,
        transfer_state=TransferState.SECRET_NOT_REQUESTED,
    )
    transfer(
        initiator_app=app1,
        target_app=app0,
        token_address=token_address,
        amount=7,
        identifier=2,
        transfer_state=TransferState.SECRET_NOT_REQUESTED,
    )

    token_network_address = views.get_token_network_address_by_token_address(
        chain_state=views.state_from_raiden(app0.raiden),
        payment_network_address=payment_network_address,
        token_address=token_address,
    )
    channel_state = get_channelstate(
        app0=app0, app1=app1, token_network_address=token_network_address
    )

    channel = app0.raiden.chain.payment_channel(channel_state.canonical_identifier)
    balance_proof = channel_state.partner_state.balance_proof
    block_number = app0.raiden.chain.block_number()

    closing_data = pack_signed_balance_proof(
        nonce=balance_proof.nonce,
        balance_hash=balance_proof.balance_hash,
        additional_hash=balance_proof.message_hash,
        canonical_identifier=balance_proof.canonical_identifier,
        partner_signature=balance_proof.signature,
    )
    closing_signature = app0.raiden.signer.sign(data=closing_data)

    channel.close(
        nonce=balance_proof.nonce,
        balance_hash=balance_proof.balance_hash,
        additional_hash=balance_proof.message_hash,
        non_closing_signature=balance_proof.signature,
        closing_signature=closing_signature,
        block_identifier=block_number,
    )

    close_block = app0.raiden.chain.block_number()

    app0.stop()

    waiting.wait_for_settle(
        raiden=app1.raiden,
        payment_network_address=payment_network_address,
        token_address=token_address,
        channel_ids=[channel_state.canonical_identifier.channel_identifier],
        retry_timeout=1,
    )

    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcWithStorageTest")
    iterations = 1000

    def send_transaction():
        check_block = deploy_client.get_checking_block()
        startgas = contract_proxy.estimate_gas(check_block, "waste_storage", iterations)
        startgas = safe_gas_limit(startgas)
        transaction = contract_proxy.transact("waste_storage", startgas, iterations)
        deploy_client.poll(transaction)
        return deploy_client.get_transaction_receipt(transaction)

    for _ in range(10):
        send_transaction()

    # The private chain used for tests has a very low pruning setting
    pruned_after_blocks = 10

    waiting.wait_for_block(
        raiden=app1.raiden, block_number=close_block + pruned_after_blocks, retry_timeout=1
    )

    channel = app0.raiden.chain.payment_channel(channel_state.canonical_identifier)

    # make sure the block was pruned
    with pytest.raises(ValueError):
        channel.detail(block_identifier=close_block)

    # This must not raise when the settle event is being raised and the
    # locksroot is being recover (#3856)
    app0.start()

    assert wait_for_state_change(
        raiden=app0.raiden,
        item_type=ContractReceiveChannelSettled,
        attributes={"canonical_identifier": channel_state.canonical_identifier},
        retry_timeout=1,
    )
