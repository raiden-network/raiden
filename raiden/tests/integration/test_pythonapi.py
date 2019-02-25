from unittest.mock import patch

import gevent
import pytest

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.constants import Environment
from raiden.exceptions import (
    AlreadyRegisteredTokenAddress,
    DepositOverLimit,
    InsufficientFunds,
    InsufficientGasReserve,
    InvalidAddress,
)
from raiden.messages import RequestMonitoring
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.events import must_have_event, wait_for_state_change
from raiden.tests.utils.factories import make_address
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.smartcontracts import deploy_contract_web3
from raiden.tests.utils.transfer import (
    assert_synced_channel_state,
    get_channelstate,
    mediated_transfer,
)
from raiden.transfer import views
from raiden.transfer.events import EventPaymentReceivedSuccess, EventPaymentSentSuccess
from raiden.transfer.state_change import ContractReceiveNewTokenNetwork
from raiden.utils import create_default_identifier
from raiden.utils.gas_reserve import (
    GAS_RESERVE_ESTIMATE_SECURITY_FACTOR,
    get_required_gas_estimate,
)
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
@pytest.mark.parametrize('environment_type', [Environment.DEVELOPMENT])
def test_register_token(raiden_network, token_amount, contract_manager, retry_timeout):
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
    exception = RuntimeError('Did not see the token registration within 30 seconds')
    with gevent.Timeout(seconds=30, exception=exception):
        wait_for_state_change(
            app1.raiden,
            ContractReceiveNewTokenNetwork,
            {
                'token_network': {
                    'token_address': token_address,
                },
            },
            retry_timeout,
        )
    assert token_address in api1.get_tokens_list(registry_address)

    # Exception if we try to reregister
    with pytest.raises(AlreadyRegisteredTokenAddress):
        api1.token_network_register(registry_address, token_address)


@pytest.mark.parametrize('privatekey_seed', ['test_token_registration:{}'])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_tokens', [1])
def test_register_token_insufficient_eth(
        raiden_network,
        token_amount,
        contract_manager,
        skip_if_parity,
):
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
    burn_eth(app1.raiden)

    # At this point we should get an UnrecoverableError due to InsufficientFunds
    with pytest.raises(InsufficientFunds):
        api1.token_network_register(registry_address, token_address)


@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('environment_type', [Environment.DEVELOPMENT])
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
    exception = RuntimeError('Did not see the token registration within 30 seconds')
    with gevent.Timeout(seconds=30, exception=exception):
        wait_for_state_change(
            app0.raiden,
            ContractReceiveNewTokenNetwork,
            {
                'token_network': {
                    'token_address': token_address,
                },
            },
            retry_timeout,
        )

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
    mediated_transfer(
        initiator_app=app0,
        target_app=app1,
        token_network_identifier=token_network_identifier,
        amount=amount,
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
    assert not result.payment_done.get()


@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [0])
def test_funds_check_for_openchannel(raiden_network, token_addresses):
    """Reproduces issue 2923 -- two open channel racing through the gas reserve"""
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]

    gas = get_required_gas_estimate(raiden=app0.raiden, channels_to_open=1)
    gas = round(gas * GAS_RESERVE_ESTIMATE_SECURITY_FACTOR)
    api0 = RaidenAPI(app0.raiden)
    burn_eth(
        raiden_service=app0.raiden,
        amount_to_leave=gas,
    )

    partners = [app1.raiden.address, app2.raiden.address]

    greenlets = [
        gevent.spawn(
            api0.channel_open,
            app0.raiden.default_registry.address,
            token_address,
            partner,
        )
        for partner in partners
    ]

    # Opening two channels needs to fail, because the gas reserve is not big enough
    # This didn't fail prior to #2977, which serializes calls to channel open,
    # so that the gas reserve checks cannot pass in parallel
    with pytest.raises(InsufficientGasReserve):
        gevent.joinall(greenlets, raise_error=True)


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('reveal_timeout', [8])
@pytest.mark.parametrize('settle_timeout', [30])
def test_payment_timing_out_if_partner_does_not_respond(
        raiden_network,
        token_addresses,
        reveal_timeout,
        skip_if_not_matrix,
        retry_timeout,
):
    """ Test to make sure that when our target does not respond payment times out

    If the target does not respond and the lock times out then the payment will
    timeout. Note that at the moment we don't retry other routes even if they
    exist when the lock expires for this transfer.

    Issue: https://github.com/raiden-network/raiden/issues/3094"""
    app0, app1 = raiden_network
    token_address = token_addresses[0]

    def fake_receive(room, event):
        return True

    with patch.object(app1.raiden.transport, '_handle_message', side_effect=fake_receive):
        greenlet = gevent.spawn(
            RaidenAPI(app0.raiden).transfer,
            app0.raiden.default_registry.address,
            token_address,
            1,
            target=app1.raiden.address,
        )
        waiting.wait_for_block(
            app0.raiden,
            app1.raiden.get_block_number() + 2 * reveal_timeout + 1,
            retry_timeout,
        )
        greenlet.join(timeout=5)
        assert not greenlet.value


@pytest.mark.parametrize('privatekey_seed', ['test_set_deposit_limit_crash:{}'])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('token_amount', [90000000000000000000000])
@pytest.mark.parametrize('environment_type', [Environment.DEVELOPMENT])
def test_set_deposit_limit_crash(raiden_network, token_amount, contract_manager, retry_timeout):
    """The development contracts as of 10/12/2018 were crashing if more than an amount was given
    Regression test for https://github.com/raiden-network/raiden/issues/3135
    """
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
    exception = RuntimeError('Did not see the token registration within 30 seconds')
    with gevent.Timeout(seconds=30, exception=exception):
        wait_for_state_change(
            app1.raiden,
            ContractReceiveNewTokenNetwork,
            {
                'token_network': {
                    'token_address': token_address,
                },
            },
            retry_timeout,
        )
    assert token_address in api1.get_tokens_list(registry_address)

    partner_address = make_address()
    api1.channel_open(
        registry_address=app1.raiden.default_registry.address,
        token_address=token_address,
        partner_address=partner_address,
    )
    with pytest.raises(DepositOverLimit):
        api1.set_total_channel_deposit(
            registry_address=app1.raiden.default_registry.address,
            token_address=token_address,
            partner_address=partner_address,
            total_deposit=10000000000000000000000,
        )


@pytest.mark.parametrize('deposit', [10])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_create_monitoring_request(
        raiden_network,
        number_of_nodes,
        deposit,
        token_addresses,
        network_wait,
        chain_id,
):
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state=chain_state,
        payment_network_id=payment_network_id,
        token_address=token_address,
    )

    payment_identifier = create_default_identifier()
    mediated_transfer(
        initiator_app=app1,
        target_app=app0,
        token_network_identifier=token_network_identifier,
        amount=1,
        identifier=payment_identifier,
    )
    chain_state = views.state_from_raiden(app0.raiden)
    channel_state = views.get_channelstate_by_token_network_and_partner(
        chain_state,
        token_network_identifier,
        app1.raiden.address,
    )
    balance_proof = channel_state.partner_state.balance_proof
    api = RaidenAPI(app0.raiden)
    request = api.create_monitoring_request(
        balance_proof=balance_proof,
        reward_amount=1,
    )
    assert request
    as_dict = request.to_dict()
    from_dict = RequestMonitoring.from_dict(as_dict)
    assert from_dict.to_dict() == as_dict
