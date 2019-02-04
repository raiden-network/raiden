import pytest

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.constants import EMPTY_HASH, EMPTY_SIGNATURE
from raiden.network.proxies import TokenNetwork
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import get_channelstate, mediated_transfer
from raiden.transfer import views
from raiden.transfer.state_change import ContractReceiveChannelSettled


@pytest.mark.parametrize('deposit', [10])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_node_can_settle_if_close_didnt_use_any_balance_proof(
        raiden_network,
        number_of_nodes,
        deposit,
        token_addresses,
        network_wait,
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
    payment_network_id = app0.raiden.default_registry.address
    registry_address = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state=chain_state,
        payment_network_id=payment_network_id,
        token_address=token_address,
    )
    channel_identifier = get_channelstate(app0, app1, token_network_identifier).identifier

    # make a transfer from app0 to app1 so that app1 is supposed to have a non
    # empty balance hash
    mediated_transfer(
        initiator_app=app0,
        target_app=app1,
        token_network_identifier=token_network_identifier,
        amount=1,
        timeout=network_wait * number_of_nodes,
    )
    # stop app1 - the test uses token_network_contract now
    app1.stop()
    token_network_contract = TokenNetwork(
        jsonrpc_client=app1.raiden.chain.client,
        token_network_address=token_network_identifier,
        contract_manager=app1.raiden.contract_manager,
    )

    # app1 closes the channel with an empty hash instead of the expected hash
    # of the transferred amount from app0
    token_network_contract.close(
        channel_identifier=channel_identifier,
        partner=app0.raiden.address,
        balance_hash=EMPTY_HASH,
        nonce=0,
        additional_hash=EMPTY_HASH,
        signature=EMPTY_SIGNATURE,
        given_block_identifier='latest',
    )
    waiting.wait_for_close(
        raiden=app0.raiden,
        payment_network_id=registry_address,
        token_address=token_address,
        channel_ids=[channel_identifier],
        retry_timeout=app0.raiden.alarm.sleep_time,
    )
    waiting.wait_for_settle(
        raiden=app0.raiden,
        payment_network_id=registry_address,
        token_address=token_address,
        channel_ids=[channel_identifier],
        retry_timeout=app0.raiden.alarm.sleep_time,
    )
    state_changes = app0.raiden.wal.storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )
    assert search_for_item(state_changes, ContractReceiveChannelSettled, {
        'token_network_identifier': token_network_identifier,
        'channel_identifier': channel_identifier,
    })


@pytest.mark.parametrize('deposit', [10])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_node_can_settle_if_partner_does_not_call_update_transfer(
        raiden_network,
        number_of_nodes,
        deposit,
        token_addresses,
        network_wait,
        chain_id,
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
    payment_network_id = app0.raiden.default_registry.address
    registry_address = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state=chain_state,
        payment_network_id=payment_network_id,
        token_address=token_address,
    )
    channel_identifier = get_channelstate(app0, app1, token_network_identifier).identifier

    mediated_transfer(
        initiator_app=app0,
        target_app=app1,
        token_network_identifier=token_network_identifier,
        amount=1,
        timeout=network_wait * number_of_nodes,
    )
    # stop app1 - the test uses token_network_contract now
    app1.stop()
    RaidenAPI(app0.raiden).channel_close(
        registry_address=registry_address,
        token_address=token_address,
        partner_address=app1.raiden.address,
    )
    waiting.wait_for_close(
        raiden=app0.raiden,
        payment_network_id=registry_address,
        token_address=token_address,
        channel_ids=[channel_identifier],
        retry_timeout=app0.raiden.alarm.sleep_time,
    )

    # app1 won't update the channel

    waiting.wait_for_settle(
        raiden=app0.raiden,
        payment_network_id=registry_address,
        token_address=token_address,
        channel_ids=[channel_identifier],
        retry_timeout=app0.raiden.alarm.sleep_time,
    )
    state_changes = app0.raiden.wal.storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )
    assert search_for_item(state_changes, ContractReceiveChannelSettled, {
        'token_network_identifier': token_network_identifier,
        'channel_identifier': channel_identifier,
    })
