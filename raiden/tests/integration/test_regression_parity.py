import pytest

from raiden import waiting
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import wait_for_state_change
from raiden.tests.utils.transfer import TransferState, get_channelstate, transfer
from raiden.transfer import views
from raiden.transfer.state_change import ContractReceiveChannelSettled

pytestmark = pytest.mark.usefixtures("skip_if_not_parity")

# set very low values to force the client to prune old state
STATE_PRUNNING = {
    "pruning": "fast",
    "pruning-history": 1,
    "pruning-memory": 1,
    "cache-size-db": 1,
    "cache-size-blocks": 1,
    "cache-size-queue": 1,
    "cache-size": 1,
}


@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("blockchain_extra_config", [STATE_PRUNNING])
def test_locksroot_loading_during_channel_settle_handling(raiden_chain, token_addresses):
    raise_on_failure(
        raiden_chain,
        run_test_locksroot_loading_during_channel_settle_handling,
        raiden_chain=raiden_chain,
        token_addresses=token_addresses,
    )


def run_test_locksroot_loading_during_channel_settle_handling(raiden_chain, token_addresses):
    app0, app1 = raiden_chain
    payment_network_id = app0.raiden.default_registry.address
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

    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state=views.state_from_raiden(app0.raiden),
        payment_network_id=payment_network_id,
        token_address=token_address,
    )
    channel_state = get_channelstate(
        app0=app0, app1=app1, token_network_identifier=token_network_identifier
    )

    channel = app0.raiden.chain.payment_channel(channel_state.canonical_identifier)
    balance_proof = channel_state.partner_state.balance_proof
    block_number = app0.raiden.chain.block_number()

    channel.close(
        nonce=balance_proof.nonce,
        balance_hash=balance_proof.balance_hash,
        additional_hash=balance_proof.message_hash,
        signature=balance_proof.signature,
        block_identifier=block_number,
    )

    app0.stop()

    waiting.wait_for_settle(
        raiden=app1.raiden,
        payment_network_id=payment_network_id,
        token_address=token_address,
        channel_ids=[channel_state.canonical_identifier.channel_identifier],
        retry_timeout=1,
    )

    # The private chain used for tests has a very low pruning setting
    pruned_after_blocks = 10
    close_event_pruned_at = app1.raiden.chain.get_block_number() + pruned_after_blocks
    waiting.wait_for_block(raiden=app1.raiden, block_number=close_event_pruned_at, retry_timeout=1)

    # make sure the block was pruned
    with pytest.raises(ValueError, match="pruned"):
        channel = app0.raiden.chain.payment_channel(channel_state.canonical_identifier)
        channel.detail(block_identifier=close_event_pruned_at)

    # This must not raise when the settle event is being raised and the
    # locksroot is being recover (#3856)
    app0.start()

    assert wait_for_state_change(
        raiden=app0.raiden,
        item_type=ContractReceiveChannelSettled,
        attributes={"canonical_identifier": channel_state.canonical_identifier},
        retry_timeout=1,
    )
