from typing import cast

import gevent
import pytest
from eth_utils import to_checksum_address

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.app import App
from raiden.constants import UINT256_MAX, Environment
from raiden.exceptions import (
    AlreadyRegisteredTokenAddress,
    DepositMismatch,
    DepositOverLimit,
    InsufficientEth,
    InsufficientGasReserve,
    InvalidBinaryAddress,
    InvalidSettleTimeout,
    TokenNotRegistered,
    UnexpectedChannelState,
    UnknownTokenAddress,
)
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.storage.serialization import DictSerializer
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import must_have_event, wait_for_state_change
from raiden.tests.utils.factories import make_address
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.smartcontracts import deploy_contract_web3
from raiden.tests.utils.transfer import get_channelstate, transfer
from raiden.transfer import channel, views
from raiden.transfer.architecture import BalanceProofSignedState
from raiden.transfer.events import (
    EventPaymentReceivedSuccess,
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
)
from raiden.transfer.mediated_transfer.events import SendSecretRequest
from raiden.transfer.state import ChannelState, NetworkState
from raiden.transfer.state_change import (
    ContractReceiveChannelSettled,
    ContractReceiveNewTokenNetwork,
)
from raiden.utils import create_default_identifier
from raiden.utils.gas_reserve import (
    GAS_RESERVE_ESTIMATE_SECURITY_FACTOR,
    get_required_gas_estimate,
)
from raiden.utils.typing import (
    BlockNumber,
    List,
    PaymentAmount,
    PaymentID,
    TokenAddress,
    TokenAmount,
)
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN, ChannelEvent
from raiden_contracts.contract_manager import ContractManager


@raise_on_failure
@pytest.mark.parametrize("privatekey_seed", ["test_token_registration:{}"])
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [1])
@pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT])
def test_register_token(raiden_network, retry_timeout, unregistered_token):
    app1 = raiden_network[0]
    registry_address = app1.raiden.default_registry.address
    token_address = unregistered_token

    # Wait until Raiden can start using the token contract.
    # Here, the block at which the contract was deployed should be confirmed by Raiden.
    # Therefore, until that block is received.
    waiting.wait_for_block(
        raiden=app1.raiden,
        block_number=app1.raiden.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1,
        retry_timeout=retry_timeout,
    )

    api1 = RaidenAPI(app1.raiden)
    assert token_address not in api1.get_tokens_list(registry_address)

    api1.token_network_register(
        registry_address=registry_address,
        token_address=token_address,
        channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
        token_network_deposit_limit=TokenAmount(UINT256_MAX),
    )
    exception = RuntimeError("Did not see the token registration within 30 seconds")
    with gevent.Timeout(seconds=30, exception=exception):
        wait_for_state_change(
            app1.raiden,
            ContractReceiveNewTokenNetwork,
            {"token_network": {"token_address": token_address}},
            retry_timeout,
        )
    assert token_address in api1.get_tokens_list(registry_address)

    # Exception if we try to reregister
    with pytest.raises(AlreadyRegisteredTokenAddress):
        api1.token_network_register(
            registry_address=registry_address,
            token_address=token_address,
            channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
            token_network_deposit_limit=TokenAmount(UINT256_MAX),
        )


@raise_on_failure
@pytest.mark.parametrize("privatekey_seed", ["test_token_registration:{}"])
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [1])
def test_register_token_insufficient_eth(raiden_network, retry_timeout, unregistered_token):
    app1 = raiden_network[0]
    registry_address = app1.raiden.default_registry.address
    token_address = unregistered_token

    # Wait until Raiden can start using the token contract.
    # Here, the block at which the contract was deployed should be confirmed by Raiden.
    # Therefore, until that block is received.
    waiting.wait_for_block(
        raiden=app1.raiden,
        block_number=app1.raiden.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1,
        retry_timeout=retry_timeout,
    )

    api1 = RaidenAPI(app1.raiden)
    assert token_address not in api1.get_tokens_list(registry_address)

    # app1.raiden loses all its ETH because it has been naughty
    burn_eth(app1.raiden.rpc_client)

    with pytest.raises(InsufficientEth):
        api1.token_network_register(
            registry_address=registry_address,
            token_address=token_address,
            channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
            token_network_deposit_limit=TokenAmount(UINT256_MAX),
        )


@raise_on_failure
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("number_of_tokens", [1])
@pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT])
def test_token_registered_race(raiden_chain, retry_timeout, unregistered_token):
    """If a token is registered it must appear on the token list.

    If two nodes register the same token one of the transactions will fail. The
    node that receives an error for "already registered token" must see the
    token in the token list. Issue: #784
    """
    app0, app1 = raiden_chain
    token_address = unregistered_token

    api0 = RaidenAPI(app0.raiden)
    api1 = RaidenAPI(app1.raiden)

    # Recreate the race condition by making sure the non-registering app won't
    # register at all by watching for the TokenAdded blockchain event.
    event_listeners = app1.raiden.blockchain_events.event_listeners
    app1.raiden.blockchain_events.event_listeners = list()

    # Wait until Raiden can start using the token contract.
    # Here, the block at which the contract was deployed should be confirmed by Raiden.
    # Therefore, until that block is received.
    waiting.wait_for_block(
        raiden=app0.raiden,
        block_number=app0.raiden.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1,
        retry_timeout=retry_timeout,
    )
    waiting.wait_for_block(
        raiden=app1.raiden,
        block_number=app1.raiden.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1,
        retry_timeout=retry_timeout,
    )

    registry_address = app0.raiden.default_registry.address
    assert token_address not in api0.get_tokens_list(registry_address)
    assert token_address not in api1.get_tokens_list(registry_address)

    api0.token_network_register(
        registry_address=registry_address,
        token_address=token_address,
        channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
        token_network_deposit_limit=TokenAmount(UINT256_MAX),
    )
    exception = RuntimeError("Did not see the token registration within 30 seconds")
    with gevent.Timeout(seconds=30, exception=exception):
        wait_for_state_change(
            app0.raiden,
            ContractReceiveNewTokenNetwork,
            {"token_network": {"token_address": token_address}},
            retry_timeout,
        )

    assert token_address in api0.get_tokens_list(registry_address)
    assert token_address not in api1.get_tokens_list(registry_address)

    # The next time when the event is polled, the token is registered
    app1.raiden.blockchain_events.event_listeners = event_listeners
    waiting.wait_for_block(app1.raiden, app1.raiden.get_block_number() + 1, retry_timeout)

    assert token_address in api1.get_tokens_list(registry_address)


@raise_on_failure
@pytest.mark.parametrize("channels_per_node", [1])
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("number_of_tokens", [1])
def test_deposit_updates_balance_immediately(raiden_chain, token_addresses):
    """ Test that the balance of a channel gets updated by the deposit() call
    immediately and without having to wait for the
    `ContractReceiveChannelDeposit` message since the API needs to return
    the channel with the deposit balance updated.
    """
    app0, app1 = raiden_chain
    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), app0.raiden.default_registry.address, token_address
    )
    assert token_network_address

    api0 = RaidenAPI(app0.raiden)

    old_state = get_channelstate(app0, app1, token_network_address)
    api0.set_total_channel_deposit(
        registry_address, token_address, app1.raiden.address, TokenAmount(210)
    )
    new_state = get_channelstate(app0, app1, token_network_address)

    assert new_state.our_state.contract_balance == old_state.our_state.contract_balance + 10


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
def test_transfer_to_unknownchannel(raiden_network, token_addresses):
    app0, _ = raiden_network
    token_address = token_addresses[0]
    str_address = "\xf0\xef3\x01\xcd\xcfe\x0f4\x9c\xf6d\xa2\x01?X4\x84\xa9\xf1"

    # Enforce sandwich encoding. Calling `transfer` with a non binary address
    # raises an exception
    with pytest.raises(InvalidBinaryAddress):
        RaidenAPI(app0.raiden).transfer(  # type: ignore
            app0.raiden.default_registry.address,
            token_address,
            10,
            target=str_address,
            transfer_timeout=10,
        )


@raise_on_failure
@pytest.mark.parametrize("channels_per_node", [1])
@pytest.mark.parametrize("number_of_nodes", [2])
def test_api_channel_events(raiden_chain, token_addresses):
    app0, app1 = raiden_chain
    token_address = token_addresses[0]

    amount = PaymentAmount(30)
    transfer(
        initiator_app=app0,
        target_app=app1,
        token_address=token_address,
        amount=amount,
        identifier=PaymentID(1),
    )

    app0_events = RaidenAPI(app0.raiden).get_blockchain_events_channel(
        token_address, app1.raiden.address
    )

    assert must_have_event(app0_events, {"event": ChannelEvent.DEPOSIT})

    app0_events = app0.raiden.wal.storage.get_events()
    assert any(isinstance(event, EventPaymentSentSuccess) for event in app0_events)

    app1_events = app1.raiden.wal.storage.get_events()
    assert any(isinstance(event, EventPaymentReceivedSuccess) for event in app1_events)

    app1_events = RaidenAPI(app1.raiden).get_blockchain_events_channel(
        token_address, app0.raiden.address
    )
    assert must_have_event(app1_events, {"event": ChannelEvent.DEPOSIT})


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
def test_insufficient_funds(raiden_network, token_addresses, deposit):
    app0, app1 = raiden_network
    token_address = token_addresses[0]

    result = RaidenAPI(app0.raiden).transfer(
        app0.raiden.default_registry.address,
        token_address,
        deposit + 1,
        target=app1.raiden.address,
    )
    assert isinstance(result.payment_done.get(), EventPaymentSentFailed)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("channels_per_node", [0])
def test_funds_check_for_openchannel(raiden_network, token_addresses):
    """Reproduces issue 2923 -- two open channel racing through the gas reserve"""
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]

    gas = get_required_gas_estimate(raiden=app0.raiden, channels_to_open=1)
    gas = round(gas * GAS_RESERVE_ESTIMATE_SECURITY_FACTOR)
    api0 = RaidenAPI(app0.raiden)
    burn_eth(rpc_client=app0.raiden.rpc_client, amount_to_leave=gas)

    partners = [app1.raiden.address, app2.raiden.address]

    greenlets = set(
        gevent.spawn(
            api0.channel_open, app0.raiden.default_registry.address, token_address, partner
        )
        for partner in partners
    )

    # Opening two channels needs to fail, because the gas reserve is not big enough
    # This didn't fail prior to #2977, which serializes calls to channel open,
    # so that the gas reserve checks cannot pass in parallel
    with pytest.raises(InsufficientGasReserve):
        gevent.joinall(greenlets, raise_error=True)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
@pytest.mark.parametrize("reveal_timeout", [8])
@pytest.mark.parametrize("settle_timeout", [30])
def test_payment_timing_out_if_partner_does_not_respond(  # pylint: disable=unused-argument
    raiden_network, token_addresses, reveal_timeout, retry_timeout
):
    """ Test to make sure that when our target does not respond payment times out

    If the target does not respond and the lock times out then the payment will
    timeout. Note that at the moment we don't retry other routes even if they
    exist when the lock expires for this transfer.

    Issue: https://github.com/raiden-network/raiden/issues/3094"""

    app0, app1 = raiden_network
    token_address = token_addresses[0]

    app1.raiden.raiden_event_handler.hold(SendSecretRequest, {})

    greenlet = gevent.spawn(
        RaidenAPI(app0.raiden).transfer,
        app0.raiden.default_registry.address,
        token_address,
        1,
        target=app1.raiden.address,
    )
    waiting.wait_for_block(
        app0.raiden, app1.raiden.get_block_number() + 2 * reveal_timeout + 1, retry_timeout
    )
    greenlet.join(timeout=5)
    assert not greenlet.value


@raise_on_failure
@pytest.mark.parametrize("privatekey_seed", ["test_set_deposit_limit_crash:{}"])
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [0])
@pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT])
def test_participant_deposit_amount_must_be_smaller_than_the_limit(
    raiden_network: List[App], contract_manager: ContractManager, retry_timeout: float
) -> None:
    """The Python API must properly check the requested participant deposit
    will not exceed the smart contract limit.

    This is companion test for
    `test_deposit_amount_must_be_smaller_than_the_token_network_limit`. The
    participant deposit limit was introduced for the bug bounty with the PR
    https://github.com/raiden-network/raiden-contracts/pull/276/ , the limit is
    available since version 0.4.0 of the smart contract.
    """
    app1 = raiden_network[0]

    registry_address = app1.raiden.default_registry.address

    token_supply = 1_000_000
    token_address = TokenAddress(
        deploy_contract_web3(
            contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
            deploy_client=app1.raiden.rpc_client,
            contract_manager=contract_manager,
            constructor_arguments=(token_supply, 2, "raiden", "Rd"),
        )
    )

    api1 = RaidenAPI(app1.raiden)

    msg = "Token is not registered yet, it must not be in the token list."
    assert token_address not in api1.get_tokens_list(registry_address), msg

    # Wait until Raiden can start using the token contract.
    # Here, the block at which the contract was deployed should be confirmed by Raiden.
    # Therefore, until that block is received.
    waiting.wait_for_block(
        raiden=app1.raiden,
        block_number=BlockNumber(
            app1.raiden.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
        ),
        retry_timeout=retry_timeout,
    )

    token_network_participant_deposit_limit = TokenAmount(100)
    api1.token_network_register(
        registry_address=registry_address,
        token_address=token_address,
        channel_participant_deposit_limit=token_network_participant_deposit_limit,
        token_network_deposit_limit=TokenAmount(UINT256_MAX),
    )

    exception = RuntimeError("Did not see the token registration within 30 seconds")
    with gevent.Timeout(seconds=30, exception=exception):
        wait_for_state_change(
            app1.raiden,
            ContractReceiveNewTokenNetwork,
            {"token_network": {"token_address": token_address}},
            retry_timeout,
        )

    msg = "Token has been registered, yet must be available in the token list."
    assert token_address in api1.get_tokens_list(registry_address), msg

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
            total_deposit=TokenAmount(token_network_participant_deposit_limit + 1),
        )

        pytest.fail(
            "The deposit must fail if the requested deposit exceeds the participant deposit limit."
        )


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [0])
@pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT])
def test_deposit_amount_must_be_smaller_than_the_token_network_limit(
    raiden_network: List[App], contract_manager: ContractManager, retry_timeout: float
) -> None:
    """The Python API must properly check the requested deposit will not exceed
    the token network deposit limit.

    This is a regression test for #3135.

    As of version `v0.18.1` (commit 786347b23), the proxy was not properly
    checking that the requested deposit amount was smaller than the smart
    contract deposit limit. This led to two errors:

    - The error message was vague and incorrect: "Deposit amount decreased"
    - The exception used was not handled and crashed the node.

    This test checks the limit is properly check from the REST API.
    """
    app1 = raiden_network[0]

    registry_address = app1.raiden.default_registry.address

    token_supply = 1_000_000
    token_address = TokenAddress(
        deploy_contract_web3(
            contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
            deploy_client=app1.raiden.rpc_client,
            contract_manager=contract_manager,
            constructor_arguments=(token_supply, 2, "raiden", "Rd"),
        )
    )

    # Wait until Raiden can start using the token contract.
    # Here, the block at which the contract was deployed should be confirmed by Raiden.
    # Therefore, until that block is received.
    waiting.wait_for_block(
        raiden=app1.raiden,
        block_number=BlockNumber(
            app1.raiden.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
        ),
        retry_timeout=retry_timeout,
    )

    api1 = RaidenAPI(app1.raiden)

    msg = "Token is not registered yet, it must not be in the token list."
    assert token_address not in api1.get_tokens_list(registry_address), msg

    token_network_deposit_limit = TokenAmount(100)
    api1.token_network_register(
        registry_address=registry_address,
        token_address=token_address,
        channel_participant_deposit_limit=token_network_deposit_limit,
        token_network_deposit_limit=token_network_deposit_limit,
    )

    exception = RuntimeError("Did not see the token registration within 30 seconds")
    with gevent.Timeout(seconds=30, exception=exception):
        wait_for_state_change(
            app1.raiden,
            ContractReceiveNewTokenNetwork,
            {"token_network": {"token_address": token_address}},
            retry_timeout,
        )

    msg = "Token has been registered, yet must be available in the token list."
    assert token_address in api1.get_tokens_list(registry_address), msg

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
            total_deposit=TokenAmount(token_network_deposit_limit + 1),
        )

        pytest.fail(
            "The deposit must fail if the requested deposit exceeds the token "
            "network deposit limit."
        )


@raise_on_failure
@pytest.mark.parametrize("deposit", [10])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [2])
def test_create_monitoring_request(raiden_network, token_addresses):
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state=chain_state,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )
    assert token_network_address

    payment_identifier = create_default_identifier()
    transfer(
        initiator_app=app1,
        target_app=app0,
        token_address=token_address,
        amount=PaymentAmount(1),
        identifier=payment_identifier,
    )
    chain_state = views.state_from_raiden(app0.raiden)
    channel_state = views.get_channelstate_by_token_network_and_partner(
        chain_state, token_network_address, app1.raiden.address
    )
    assert channel_state
    balance_proof = cast(BalanceProofSignedState, channel_state.partner_state.balance_proof)
    api = RaidenAPI(app0.raiden)
    request = api.create_monitoring_request(
        balance_proof=balance_proof, reward_amount=TokenAmount(1)
    )
    assert request
    as_dict = DictSerializer.serialize(request)
    from_dict = DictSerializer.deserialize(as_dict)
    assert DictSerializer.serialize(from_dict) == as_dict


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("number_of_tokens", [1])
def test_token_addresses(raiden_network, token_addresses):
    """
    Test that opening a channel via the API provides the confirmed block and not
    the latest block. The discrepancy there lead to potential timing issues where
    the token network was deployed for the state in the "latest" block but not yet
    in the confirmed state and a BadFunctionCallOutput exception was thrown from web3.

    Regression test for 4470
    """
    app0, app1 = raiden_network
    token_address = token_addresses[0]

    # Find block where the token network was deployed
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), app0.raiden.default_registry.address, token_address
    )
    last_number = app0.raiden.rpc_client.block_number()

    for block_number in range(last_number, 0, -1):
        code = app0.raiden.rpc_client.web3.eth.getCode(
            account=token_network_address, block_identifier=block_number
        )
        if code == b"":
            break
    token_network_deploy_block_number = block_number + 1

    api0 = RaidenAPI(app0.raiden)
    # Emulate the confirmed block being a block where TokenNetwork for token_address
    # has not been deployed.
    views.state_from_raiden(app0.raiden).block_hash = app0.raiden.rpc_client.get_block(
        token_network_deploy_block_number - 1
    )["hash"]

    msg = (
        "Opening a channel with a confirmed block where the token network "
        "has not yet been deployed should raise a TokenNotRegistered error"
    )
    with pytest.raises(TokenNotRegistered):
        api0.channel_open(
            registry_address=app0.raiden.default_registry.address,
            token_address=token_address,
            partner_address=app1.raiden.address,
        )

        pytest.fail(msg)


def run_test_token_addresses(raiden_network, token_addresses):
    app = raiden_network[0]
    api = RaidenAPI(app.raiden)
    registry_address = app.raiden.default_registry.address
    assert set(api.get_tokens_list(registry_address)) == set(token_addresses)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [0])
def test_raidenapi_channel_lifecycle(
    raiden_network, token_addresses, deposit, retry_timeout, settle_timeout_max
):
    """Uses RaidenAPI to go through a complete channel lifecycle."""
    node1, node2 = raiden_network
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(node1), node1.raiden.default_registry.address, token_address
    )
    assert token_network_address

    api1 = RaidenAPI(node1.raiden)
    api2 = RaidenAPI(node2.raiden)

    registry_address = node1.raiden.default_registry.address

    # nodes don't have a channel, so they are not healthchecking
    assert api1.get_node_network_state(api2.address) == NetworkState.UNKNOWN
    assert api2.get_node_network_state(api1.address) == NetworkState.UNKNOWN
    assert not api1.get_channel_list(registry_address, token_address, api2.address)

    # Make sure invalid arguments to get_channel_list are caught
    with pytest.raises(UnknownTokenAddress):
        api1.get_channel_list(
            registry_address=registry_address, token_address=None, partner_address=api2.address
        )

    address_for_lowest_settle_timeout = make_address()
    lowest_valid_settle_timeout = node1.raiden.config["reveal_timeout"] * 2

    # Make sure a small settle timeout is not accepted when opening a channel
    with pytest.raises(InvalidSettleTimeout):
        api1.channel_open(
            registry_address=node1.raiden.default_registry.address,
            token_address=token_address,
            partner_address=address_for_lowest_settle_timeout,
            settle_timeout=lowest_valid_settle_timeout - 1,
        )

    # Make sure the smallest settle timeout is accepted
    api1.channel_open(
        registry_address=node1.raiden.default_registry.address,
        token_address=token_address,
        partner_address=address_for_lowest_settle_timeout,
        settle_timeout=lowest_valid_settle_timeout,
    )

    address_for_highest_settle_timeout = make_address()
    highest_valid_settle_timeout = settle_timeout_max

    # Make sure a large settle timeout is not accepted when opening a channel
    with pytest.raises(InvalidSettleTimeout):
        api1.channel_open(
            registry_address=node1.raiden.default_registry.address,
            token_address=token_address,
            partner_address=address_for_highest_settle_timeout,
            settle_timeout=highest_valid_settle_timeout + 1,
        )

    # Make sure the highest settle timeout is accepted
    api1.channel_open(
        registry_address=node1.raiden.default_registry.address,
        token_address=token_address,
        partner_address=address_for_highest_settle_timeout,
        settle_timeout=highest_valid_settle_timeout,
    )

    # open is a synchronous api
    api1.channel_open(node1.raiden.default_registry.address, token_address, api2.address)
    channels = api1.get_channel_list(registry_address, token_address, api2.address)
    assert len(channels) == 1

    channel12 = get_channelstate(node1, node2, token_network_address)
    assert channel.get_status(channel12) == ChannelState.STATE_OPENED

    channel_event_list1 = api1.get_blockchain_events_channel(
        token_address, channel12.partner_state.address
    )
    assert must_have_event(
        channel_event_list1,
        {
            "event": ChannelEvent.OPENED,
            "args": {
                "participant1": to_checksum_address(api1.address),
                "participant2": to_checksum_address(api2.address),
            },
        },
    )

    network_event_list1 = api1.get_blockchain_events_token_network(token_address)
    assert must_have_event(network_event_list1, {"event": ChannelEvent.OPENED})

    registry_address = api1.raiden.default_registry.address
    # Check that giving a 0 total deposit is not accepted
    with pytest.raises(DepositMismatch):
        api1.set_total_channel_deposit(
            registry_address=registry_address,
            token_address=token_address,
            partner_address=api2.address,
            total_deposit=TokenAmount(0),
        )
    # Load the new state with the deposit
    api1.set_total_channel_deposit(
        registry_address=registry_address,
        token_address=token_address,
        partner_address=api2.address,
        total_deposit=deposit,
    )

    # let's make sure it's idempotent. Same deposit should raise deposit mismatch limit
    with pytest.raises(DepositMismatch):
        api1.set_total_channel_deposit(registry_address, token_address, api2.address, deposit)

    channel12 = get_channelstate(node1, node2, token_network_address)

    assert channel.get_status(channel12) == ChannelState.STATE_OPENED
    assert channel.get_balance(channel12.our_state, channel12.partner_state) == deposit
    assert channel12.our_state.contract_balance == deposit
    assert api1.get_channel_list(registry_address, token_address, api2.address) == [channel12]

    # there is a channel open, they must be healthchecking each other
    assert api1.get_node_network_state(api2.address) == NetworkState.REACHABLE
    assert api2.get_node_network_state(api1.address) == NetworkState.REACHABLE

    event_list2 = api1.get_blockchain_events_channel(
        token_address, channel12.partner_state.address
    )
    assert must_have_event(
        event_list2,
        {
            "event": ChannelEvent.DEPOSIT,
            "args": {"participant": to_checksum_address(api1.address), "total_deposit": deposit},
        },
    )

    api1.channel_close(registry_address, token_address, api2.address)

    # Load the new state with the channel closed
    channel12 = get_channelstate(node1, node2, token_network_address)

    event_list3 = api1.get_blockchain_events_channel(
        token_address, channel12.partner_state.address
    )
    assert len(event_list3) > len(event_list2)
    assert must_have_event(
        event_list3,
        {
            "event": ChannelEvent.CLOSED,
            "args": {"closing_participant": to_checksum_address(api1.address)},
        },
    )
    assert channel.get_status(channel12) == ChannelState.STATE_CLOSED

    with pytest.raises(UnexpectedChannelState):
        api1.set_total_channel_deposit(
            registry_address, token_address, api2.address, deposit + 100
        )

    assert wait_for_state_change(
        node1.raiden,
        ContractReceiveChannelSettled,
        {
            "canonical_identifier": {
                "token_network_address": token_network_address,
                "channel_identifier": channel12.identifier,
            }
        },
        retry_timeout,
    )
