import gevent
import pytest

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.exceptions import AlreadyRegisteredTokenAddress, InsufficientFunds, InvalidAddress
from raiden.tests.utils.client import burn_all_eth
from raiden.tests.utils.events import must_have_event
from raiden.tests.utils.smartcontracts import deploy_contract_web3
from raiden.tests.utils.transfer import (
    assert_synced_channel_state,
    direct_transfer,
    get_channelstate,
)
from raiden.transfer import views
from raiden.transfer.events import EventPaymentReceivedSuccess, EventPaymentSentSuccess
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN, ChannelEvent

# Use a large enough settle timeout to have valid transfer messages
TEST_TOKEN_SWAP_SETTLE_TIMEOUT = (
    5 +  # reveal timeout
    7 +  # maker expiration
    7    # taker expiration
)


@pytest.mark.parametrize('privatekey_seed', ['test_token_registration:{}'])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.skip('token registration not working in red eyes')
def test_register_token(raiden_network, token_amount, contract_manager):
    app1 = raiden_network[0]

    registry_address = app1.raiden.default_registry.address

    token_address = deploy_contract_web3(
        contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
        deploy_client=app1.raiden.chain.client,
        contract_manager=contract_manager,
        constructor_arguments=(
            token_amount,
            2,
            'raiden',
            'Rd',
        ),
    )

    api1 = RaidenAPI(app1.raiden)
    assert token_address not in api1.get_tokens_list(registry_address)

    api1.token_network_register(registry_address, token_address)
    assert token_address in api1.get_tokens_list(registry_address)

    # Exception if we try to reregister
    with pytest.raises(AlreadyRegisteredTokenAddress):
        api1.token_network_register(registry_address, token_address)


@pytest.mark.parametrize('privatekey_seed', ['test_token_registration:{}'])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_tokens', [1])
def test_register_token_insufficient_eth(raiden_network, token_amount, contract_manager):
    app1 = raiden_network[0]

    registry_address = app1.raiden.default_registry.address

    token_address = deploy_contract_web3(
        contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
        deploy_client=app1.raiden.chain.client,
        contract_manager=contract_manager,
        constructor_arguments=(
            token_amount,
            2,
            'raiden',
            'Rd',
        ),
    )

    api1 = RaidenAPI(app1.raiden)
    assert token_address not in api1.get_tokens_list(registry_address)

    # app1.raiden loses all its ETH because it has been naughty
    burn_all_eth(app1.raiden)

    # At this point we should get the InsufficientFunds exception
    with pytest.raises(InsufficientFunds):
        api1.token_network_register(registry_address, token_address)


@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.skip('token registration not working in red eyes')
def test_token_registered_race(raiden_chain, token_amount, retry_timeout, contract_manager):
    """If a token is registered it must appear on the token list.

    If two nodes register the same token one of the transactions will fail. The
    node that receives an error for "already registered token" must see the
    token in the token list. Issue: #784
    """
    app0, app1 = raiden_chain

    api0 = RaidenAPI(app0.raiden)
    api1 = RaidenAPI(app1.raiden)

    # Recreate the race condition by making sure the non-registering app won't
    # register at all by watching for the TokenAdded blockchain event.
    event_listeners = app1.raiden.blockchain_events.event_listeners
    app1.raiden.blockchain_events.event_listeners = list()

    token_address = deploy_contract_web3(
        contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
        deploy_client=app1.raiden.chain.client,
        contract_manager=contract_manager,
        constructor_arguments=(
            token_amount,
            2,
            'raiden',
            'Rd',
        ),
    )

    gevent.sleep(1)

    registry_address = app0.raiden.default_registry.address
    assert token_address not in api0.get_tokens_list(registry_address)
    assert token_address not in api1.get_tokens_list(registry_address)

    api0.token_network_register(registry_address, token_address)

    gevent.sleep(1)

    assert token_address in api0.get_tokens_list(registry_address)
    assert token_address not in api1.get_tokens_list(registry_address)

    # The next time when the event is polled, the token is registered
    app1.raiden.blockchain_events.event_listeners = event_listeners
    waiting.wait_for_block(
        app1.raiden,
        app1.raiden.get_block_number() + 1,
        retry_timeout,
    )

    assert token_address in api1.get_tokens_list(registry_address)


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [1])
def test_deposit_updates_balance_immediately(raiden_chain, token_addresses):
    """ Test that the balance of a channel gets updated by the deposit() call
    immediately and without having to wait for the
    `ContractReceiveChannelNewBalance` message since the API needs to return
    the channel with the deposit balance updated.
    """
    app0, app1 = raiden_chain
    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )

    api0 = RaidenAPI(app0.raiden)

    old_state = get_channelstate(app0, app1, token_network_identifier)
    api0.set_total_channel_deposit(registry_address, token_address, app1.raiden.address, 210)
    new_state = get_channelstate(app0, app1, token_network_identifier)

    assert new_state.our_state.contract_balance == old_state.our_state.contract_balance + 10


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_transfer_to_unknownchannel(raiden_network, token_addresses):
    app0, _ = raiden_network
    token_address = token_addresses[0]
    non_existing_address = '\xf0\xef3\x01\xcd\xcfe\x0f4\x9c\xf6d\xa2\x01?X4\x84\xa9\xf1'

    with pytest.raises(InvalidAddress):
        # sending to an unknown/non-existant address
        RaidenAPI(app0.raiden).transfer(
            app0.raiden.default_registry.address,
            token_address,
            10,
            target=non_existing_address,
            transfer_timeout=10,
        )


@pytest.mark.skip
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [2])
@pytest.mark.parametrize('settle_timeout', [TEST_TOKEN_SWAP_SETTLE_TIMEOUT])
def test_token_swap(raiden_network, deposit, token_addresses):
    app0, app1 = raiden_network

    maker_address = app0.raiden.address
    taker_address = app1.raiden.address

    maker_token, taker_token = token_addresses[0], token_addresses[1]
    maker_amount = 70
    taker_amount = 30

    identifier = 313
    RaidenAPI(app1.raiden).expect_token_swap(  # pylint: disable=no-member
        identifier,
        maker_token,
        maker_amount,
        maker_address,
        taker_token,
        taker_amount,
        taker_address,
    )

    async_result = RaidenAPI(app0.raiden).token_swap_async(  # pylint: disable=no-member
        identifier,
        maker_token,
        maker_amount,
        maker_address,
        taker_token,
        taker_amount,
        taker_address,
    )

    assert async_result.wait()

    # wait for the taker to receive and process the messages
    gevent.sleep(0.5)

    assert_synced_channel_state(
        maker_token,
        app0, deposit - maker_amount, [],
        app1, deposit + maker_amount, [],
    )

    assert_synced_channel_state(
        taker_token,
        app0, deposit + taker_amount, [],
        app1, deposit - taker_amount, [],
    )


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_api_channel_events(raiden_chain, token_addresses):
    app0, app1 = raiden_chain
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )

    amount = 30
    direct_transfer(
        app0,
        app1,
        token_network_identifier,
        amount,
        identifier=1,
    )

    app0_events = RaidenAPI(app0.raiden).get_blockchain_events_channel(
        token_address,
        app1.raiden.address,
    )

    assert must_have_event(app0_events, {'event': ChannelEvent.DEPOSIT})

    app0_events = app0.raiden.wal.storage.get_events()
    any(isinstance(event, EventPaymentSentSuccess) for event in app0_events)

    app1_events = app1.raiden.wal.storage.get_events()
    any(isinstance(event, EventPaymentReceivedSuccess) for event in app1_events)

    app1_events = RaidenAPI(app1.raiden).get_blockchain_events_channel(
        token_address,
        app0.raiden.address,
    )
    assert must_have_event(app1_events, {'event': ChannelEvent.DEPOSIT})


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_insufficient_funds(raiden_network, token_addresses, deposit):
    app0, app1 = raiden_network
    token_address = token_addresses[0]

    result = RaidenAPI(app0.raiden).transfer(
        app0.raiden.default_registry.address,
        token_address,
        deposit + 1,
        target=app1.raiden.address,
    )
    assert not result
