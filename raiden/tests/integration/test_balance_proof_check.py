import pytest

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.constants import BLOCK_ID_LATEST, EMPTY_BALANCE_HASH, EMPTY_HASH, EMPTY_SIGNATURE
from raiden.storage.sqlite import RANGE_ALL_STATE_CHANGES
from raiden.tests.integration.network.proxies import BalanceProof
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import get_channelstate, transfer
from raiden.transfer import views
from raiden.transfer.state_change import ContractReceiveChannelSettled
from raiden.utils.typing import Nonce, PaymentAmount, PaymentID, TokenAmount, TokenNetworkAddress
from raiden_contracts.constants import MessageTypeId


@raise_on_failure
@pytest.mark.parametrize("deposit", [10])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [2])
def test_node_can_settle_if_close_didnt_use_any_balance_proof(
    raiden_network, number_of_nodes, token_addresses, network_wait
):
    """ A node must be able to settle a channel, even if the partner used an
    old balance proof to close it.

    This test will:
    - Make a transfer from app0 to app1, to make sure there are balance
    proofs available
    - Call close manually in behalf of app1, without any balance proof data
    - Assert that app0 can settle the closed channel, even though app1 didn't
    use the latest balance proof
    """
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    token_network_registry_address = app0.raiden.default_registry.address
    registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state=chain_state,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )
    assert token_network_address
    channel_identifier = get_channelstate(app0, app1, token_network_address).identifier

    # make a transfer from app0 to app1 so that app1 is supposed to have a non
    # empty balance hash
    transfer(
        initiator_app=app0,
        target_app=app1,
        token_address=token_address,
        amount=PaymentAmount(1),
        identifier=PaymentID(1),
        timeout=network_wait * number_of_nodes,
    )
    # stop app1 - the test uses token_network_contract now
    app1.stop()
    token_network_contract = app1.raiden.proxy_manager.token_network(
        token_network_address, BLOCK_ID_LATEST
    )
    empty_balance_proof = BalanceProof(
        channel_identifier=channel_identifier,
        token_network_address=TokenNetworkAddress(token_network_contract.address),
        balance_hash=EMPTY_BALANCE_HASH,
        nonce=Nonce(0),
        chain_id=chain_state.chain_id,
        transferred_amount=TokenAmount(0),
    )
    closing_data = (
        empty_balance_proof.serialize_bin(msg_type=MessageTypeId.BALANCE_PROOF) + EMPTY_SIGNATURE
    )
    closing_signature = app1.raiden.signer.sign(data=closing_data)

    # app1 closes the channel with an empty hash instead of the expected hash
    # of the transferred amount from app0
    token_network_contract.close(
        channel_identifier=channel_identifier,
        partner=app0.raiden.address,
        balance_hash=EMPTY_HASH,
        nonce=0,
        additional_hash=EMPTY_HASH,
        non_closing_signature=EMPTY_SIGNATURE,
        closing_signature=closing_signature,
        given_block_identifier=BLOCK_ID_LATEST,
    )
    waiting.wait_for_settle(
        raiden=app0.raiden,
        token_network_registry_address=registry_address,
        token_address=token_address,
        channel_ids=[channel_identifier],
        retry_timeout=app0.raiden.alarm.sleep_time,
    )
    state_changes = app0.raiden.wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)
    assert search_for_item(
        state_changes,
        ContractReceiveChannelSettled,
        {"token_network_address": token_network_address, "channel_identifier": channel_identifier},
    )


@raise_on_failure
@pytest.mark.parametrize("deposit", [10])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [2])
def test_node_can_settle_if_partner_does_not_call_update_transfer(
    raiden_network, number_of_nodes, token_addresses, network_wait
):
    """ A node must be able to settle a channel, even if the partner did not
    call update transfer.

    This test will:
    - Make a transfer from app0 to app1, to make sure there are balance
    proofs available
    - Stop app1, to make sure update is not called.
    - Use app0 to close the channel.
    - Assert that app0 can settle the closed channel, even though app1 didn't
    use the latest balance proof
    """
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    token_network_registry_address = app0.raiden.default_registry.address
    registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state=chain_state,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )
    assert token_network_address
    channel_identifier = get_channelstate(app0, app1, token_network_address).identifier

    transfer(
        initiator_app=app0,
        target_app=app1,
        token_address=token_address,
        amount=PaymentAmount(1),
        identifier=PaymentID(1),
        timeout=network_wait * number_of_nodes,
    )
    # stop app1 - the test uses token_network_contract now
    app1.stop()
    RaidenAPI(app0.raiden).channel_close(
        registry_address=registry_address,
        token_address=token_address,
        partner_address=app1.raiden.address,
    )

    # app1 won't update the channel

    waiting.wait_for_settle(
        raiden=app0.raiden,
        token_network_registry_address=registry_address,
        token_address=token_address,
        channel_ids=[channel_identifier],
        retry_timeout=app0.raiden.alarm.sleep_time,
    )
    state_changes = app0.raiden.wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)
    assert search_for_item(
        state_changes,
        ContractReceiveChannelSettled,
        {"token_network_address": token_network_address, "channel_identifier": channel_identifier},
    )
