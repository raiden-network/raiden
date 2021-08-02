from unittest.mock import patch

import gevent
import pytest
from eth_utils import to_canonical_address

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.constants import UINT256_MAX, Environment
from raiden.exceptions import (
    AlreadyRegisteredTokenAddress,
    DepositMismatch,
    DepositOverLimit,
    InsufficientEth,
    InsufficientGasReserve,
    InvalidBinaryAddress,
    InvalidSecret,
    InvalidSettleTimeout,
    RaidenRecoverableError,
    SamePeerAddress,
    TokenNotRegistered,
    UnexpectedChannelState,
    UnknownTokenAddress,
)
from raiden.raiden_service import RaidenService
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import wait_for_state_change
from raiden.tests.utils.factories import make_address
from raiden.tests.utils.protocol import HoldRaidenEventHandler
from raiden.tests.utils.transfer import get_channelstate
from raiden.transfer import channel, views
from raiden.transfer.events import EventPaymentSentFailed
from raiden.transfer.mediated_transfer.events import SendSecretRequest
from raiden.transfer.state import ChannelState, NetworkState
from raiden.transfer.state_change import (
    ContractReceiveChannelSettled,
    ContractReceiveNewTokenNetwork,
)
from raiden.utils.gas_reserve import (
    GAS_RESERVE_ESTIMATE_SECURITY_FACTOR,
    get_required_gas_estimate,
)
from raiden.utils.typing import (
    Address,
    BlockNumber,
    BlockTimeout,
    List,
    PaymentAmount,
    TargetAddress,
    TokenAddress,
    TokenAmount,
)
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN
from raiden_contracts.contract_manager import ContractManager


@raise_on_failure
@pytest.mark.parametrize("privatekey_seed", ["test_token_registration:{}"])
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [1])
@pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT])
def test_register_token(raiden_network: List[RaidenService], retry_timeout, unregistered_token):
    app1 = raiden_network[0]
    registry_address = app1.default_registry.address
    token_address = unregistered_token

    # Wait until Raiden can start using the token contract.
    # Here, the block at which the contract was deployed should be confirmed by Raiden.
    # Therefore, until that block is received.
    waiting.wait_for_block(
        raiden=app1,
        block_number=BlockNumber(
            app1.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
        ),
        retry_timeout=retry_timeout,
    )

    api1 = RaidenAPI(app1)
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
            app1,
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
def test_register_token_insufficient_eth(
    raiden_network: List[RaidenService], retry_timeout, unregistered_token
):
    app1 = raiden_network[0]
    registry_address = app1.default_registry.address
    token_address = unregistered_token

    # Wait until Raiden can start using the token contract.
    # Here, the block at which the contract was deployed should be confirmed by Raiden.
    # Therefore, until that block is received.
    waiting.wait_for_block(
        raiden=app1,
        block_number=BlockNumber(
            app1.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
        ),
        retry_timeout=retry_timeout,
    )

    api1 = RaidenAPI(app1)
    assert token_address not in api1.get_tokens_list(registry_address)

    # app1 loses all its ETH because it has been naughty
    burn_eth(app1.rpc_client)

    with pytest.raises(InsufficientEth):
        api1.token_network_register(
            registry_address=registry_address,
            token_address=token_address,
            channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
            token_network_deposit_limit=TokenAmount(UINT256_MAX),
        )


@pytest.mark.flaky
@raise_on_failure
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("number_of_tokens", [1])
@pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT])
def test_token_registered_race(
    raiden_chain: List[RaidenService], retry_timeout, unregistered_token
):
    """If a token is registered it must appear on the token list.

    If two nodes register the same token one of the transactions will fail. The
    node that receives an error for "already registered token" must see the
    token in the token list. Issue: #784
    """
    app0, app1 = raiden_chain
    token_address = unregistered_token

    api0 = RaidenAPI(app0)
    api1 = RaidenAPI(app1)

    # Wait until Raiden can start using the token contract.
    # Here, the block at which the contract was deployed should be confirmed by Raiden.
    # Therefore, until that block is received.
    waiting.wait_for_block(
        raiden=app0,
        block_number=BlockNumber(
            app0.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
        ),
        retry_timeout=retry_timeout,
    )
    waiting.wait_for_block(
        raiden=app1,
        block_number=BlockNumber(
            app1.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
        ),
        retry_timeout=retry_timeout,
    )

    registry_address = app0.default_registry.address
    assert token_address not in api0.get_tokens_list(registry_address)
    assert token_address not in api1.get_tokens_list(registry_address)

    greenlets: set = {
        gevent.spawn(
            api0.token_network_register,
            registry_address=registry_address,
            token_address=token_address,
            channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
            token_network_deposit_limit=TokenAmount(UINT256_MAX),
        ),
        gevent.spawn(
            api0.token_network_register,
            registry_address=registry_address,
            token_address=token_address,
            channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
            token_network_deposit_limit=TokenAmount(UINT256_MAX),
        ),
    }

    # One of the nodes will lose the race
    with pytest.raises(RaidenRecoverableError):
        gevent.joinall(greenlets, raise_error=True)

    exception = RuntimeError("Did not see the token registration within 30 seconds")
    with gevent.Timeout(seconds=30, exception=exception):
        wait_for_state_change(
            app0,
            ContractReceiveNewTokenNetwork,
            {"token_network": {"token_address": token_address}},
            retry_timeout,
        )
        wait_for_state_change(
            app1,
            ContractReceiveNewTokenNetwork,
            {"token_network": {"token_address": token_address}},
            retry_timeout,
        )

    assert token_address in api0.get_tokens_list(registry_address)
    assert token_address in api1.get_tokens_list(registry_address)

    for api in (api0, api1):
        with pytest.raises(AlreadyRegisteredTokenAddress):
            api.token_network_register(
                registry_address=registry_address,
                token_address=token_address,
                channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
                token_network_deposit_limit=TokenAmount(UINT256_MAX),
            )


@raise_on_failure
@pytest.mark.parametrize("channels_per_node", [1])
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("number_of_tokens", [1])
def test_deposit_updates_balance_immediately(raiden_chain: List[RaidenService], token_addresses):
    """Test that the balance of a channel gets updated by the deposit() call
    immediately and without having to wait for the
    `ContractReceiveChannelDeposit` message since the API needs to return
    the channel with the deposit balance updated.
    """
    app0, app1 = raiden_chain
    registry_address = app0.default_registry.address
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(app0), app0.default_registry.address, token_address
    )
    assert token_network_address

    api0 = RaidenAPI(app0)

    old_state = get_channelstate(app0, app1, token_network_address)
    api0.set_total_channel_deposit(registry_address, token_address, app1.address, TokenAmount(210))
    new_state = get_channelstate(app0, app1, token_network_address)

    assert new_state.our_state.contract_balance == old_state.our_state.contract_balance + 10


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
def test_transfer_with_invalid_address_type(raiden_network: List[RaidenService], token_addresses):
    app0, _ = raiden_network
    token_address = token_addresses[0]
    target_address = "\xf0\xef3\x01\xcd\xcfe\x0f4\x9c\xf6d\xa2\x01?X4\x84\xa9\xf1"

    # Enforce sandwich encoding. Calling `transfer` with a non binary address
    # raises an exception
    with pytest.raises(InvalidBinaryAddress):
        RaidenAPI(app0).transfer_and_wait(
            app0.default_registry.address,
            token_address,
            PaymentAmount(10),
            target=target_address,  # type: ignore
            transfer_timeout=10,
        )


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
def test_insufficient_funds(raiden_network: List[RaidenService], token_addresses, deposit):
    app0, app1 = raiden_network
    token_address = token_addresses[0]

    result = RaidenAPI(app0).transfer_and_wait(
        app0.default_registry.address,
        token_address,
        deposit + 1,
        target=TargetAddress(app1.address),
    )
    assert isinstance(result.payment_done.get(), EventPaymentSentFailed)


@pytest.mark.skip(
    reason=(
        "Missing synchronization, see "
        "https://github.com/raiden-network/raiden/issues/4625#issuecomment-585672612"
    )
)
@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("channels_per_node", [0])
def test_funds_check_for_openchannel(raiden_network: List[RaidenService], token_addresses):
    """Reproduces issue 2923 -- two open channel racing through the gas reserve"""
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]

    gas = get_required_gas_estimate(raiden=app0, channels_to_open=1)
    gas = round(gas * GAS_RESERVE_ESTIMATE_SECURITY_FACTOR)
    api0 = RaidenAPI(app0)
    burn_eth(rpc_client=app0.rpc_client, amount_to_leave=gas)

    partners = [app1.address, app2.address]

    greenlets = set(
        gevent.spawn(api0.channel_open, app0.default_registry.address, token_address, partner)
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
    raiden_network: List[RaidenService], token_addresses, reveal_timeout, retry_timeout
):
    """Test to make sure that when our target does not respond payment times out

    If the target does not respond and the lock times out then the payment will
    timeout. Note that at the moment we don't retry other routes even if they
    exist when the lock expires for this transfer.

    Issue: https://github.com/raiden-network/raiden/issues/3094"""

    app0, app1 = raiden_network
    token_address = token_addresses[0]

    msg = "test app must use HoldRaidenEventHandler."
    assert isinstance(app1.raiden_event_handler, HoldRaidenEventHandler), msg
    app1.raiden_event_handler.hold(SendSecretRequest, {})

    with patch("raiden.message_handler.decrypt_secret", side_effect=InvalidSecret):
        greenlet = gevent.spawn(
            RaidenAPI(app0).transfer_and_wait,
            app0.default_registry.address,
            token_address,
            1,
            target=app1.address,
        )
        waiting.wait_for_block(
            app0, app1.get_block_number() + 2 * reveal_timeout + 1, retry_timeout
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
    raiden_network: List[RaidenService], contract_manager: ContractManager, retry_timeout: float
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

    registry_address = app1.default_registry.address

    token_supply = 1_000_000
    contract_proxy, _ = app1.rpc_client.deploy_single_contract(
        contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
        contract=contract_manager.get_contract(CONTRACT_HUMAN_STANDARD_TOKEN),
        constructor_parameters=(token_supply, 2, "raiden", "Rd"),
    )
    token_address = TokenAddress(to_canonical_address(contract_proxy.address))

    api1 = RaidenAPI(app1)

    msg = "Token is not registered yet, it must not be in the token list."
    assert token_address not in api1.get_tokens_list(registry_address), msg

    # Wait until Raiden can start using the token contract.
    # Here, the block at which the contract was deployed should be confirmed by Raiden.
    # Therefore, until that block is received.
    waiting.wait_for_block(
        raiden=app1,
        block_number=BlockNumber(
            app1.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
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
            app1,
            ContractReceiveNewTokenNetwork,
            {"token_network": {"token_address": token_address}},
            retry_timeout,
        )

    msg = "Token has been registered, yet must be available in the token list."
    assert token_address in api1.get_tokens_list(registry_address), msg

    partner_address = make_address()
    api1.channel_open(
        registry_address=app1.default_registry.address,
        token_address=token_address,
        partner_address=partner_address,
    )

    with pytest.raises(DepositOverLimit):
        api1.set_total_channel_deposit(
            registry_address=app1.default_registry.address,
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
    raiden_network: List[RaidenService], contract_manager: ContractManager, retry_timeout: float
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

    registry_address = app1.default_registry.address

    token_supply = 1_000_000
    contract_proxy, _ = app1.rpc_client.deploy_single_contract(
        contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
        contract=contract_manager.get_contract(CONTRACT_HUMAN_STANDARD_TOKEN),
        constructor_parameters=(token_supply, 2, "raiden", "Rd"),
    )
    token_address = TokenAddress(to_canonical_address(contract_proxy.address))

    # Wait until Raiden can start using the token contract.
    # Here, the block at which the contract was deployed should be confirmed by Raiden.
    # Therefore, until that block is received.
    waiting.wait_for_block(
        raiden=app1,
        block_number=BlockNumber(
            app1.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
        ),
        retry_timeout=retry_timeout,
    )

    api1 = RaidenAPI(app1)

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
            app1,
            ContractReceiveNewTokenNetwork,
            {"token_network": {"token_address": token_address}},
            retry_timeout,
        )

    msg = "Token has been registered, yet must be available in the token list."
    assert token_address in api1.get_tokens_list(registry_address), msg

    partner_address = make_address()
    api1.channel_open(
        registry_address=app1.default_registry.address,
        token_address=token_address,
        partner_address=partner_address,
    )

    with pytest.raises(DepositOverLimit):
        api1.set_total_channel_deposit(
            registry_address=app1.default_registry.address,
            token_address=token_address,
            partner_address=partner_address,
            total_deposit=TokenAmount(token_network_deposit_limit + 1),
        )

        pytest.fail(
            "The deposit must fail if the requested deposit exceeds the token "
            "network deposit limit."
        )


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("number_of_tokens", [1])
def test_token_addresses(raiden_network: List[RaidenService], token_addresses):
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
        views.state_from_raiden(app0), app0.default_registry.address, token_address
    )
    assert token_network_address, "token_address must be registered by the fixtures."

    last_number = app0.rpc_client.block_number()

    for block_number in range(last_number, 0, -1):
        code = app0.rpc_client.web3.eth.get_code(
            account=Address(token_network_address), block_identifier=block_number
        )
        if code == b"":
            break
    token_network_deploy_block_number = block_number + 1

    api0 = RaidenAPI(app0)
    # Emulate the confirmed block being a block where TokenNetwork for token_address
    # has not been deployed.
    views.state_from_raiden(app0).block_hash = app0.rpc_client.get_block(  # type: ignore
        token_network_deploy_block_number - 1
    )["hash"]

    msg = (
        "Opening a channel with a confirmed block where the token network "
        "has not yet been deployed should raise a TokenNotRegistered error"
    )
    with pytest.raises(TokenNotRegistered):
        api0.channel_open(
            registry_address=app0.default_registry.address,
            token_address=token_address,
            partner_address=app1.address,
        )

        pytest.fail(msg)


def run_test_token_addresses(raiden_network: List[RaidenService], token_addresses):
    app = raiden_network[0]
    api = RaidenAPI(app)
    registry_address = app.default_registry.address
    assert set(api.get_tokens_list(registry_address)) == set(token_addresses)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [0])
def test_raidenapi_channel_lifecycle(
    raiden_network: List[RaidenService],
    token_addresses,
    deposit,
    retry_timeout,
    settle_timeout_max,
):
    """Uses RaidenAPI to go through a complete channel lifecycle."""
    app1, app2 = raiden_network
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(app1), app1.default_registry.address, token_address
    )
    assert token_network_address

    api1 = RaidenAPI(app1)
    api2 = RaidenAPI(app2)

    registry_address = app1.default_registry.address

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
    lowest_valid_settle_timeout = app1.config.reveal_timeout * 2

    # Make sure a small settle timeout is not accepted when opening a channel
    with pytest.raises(InvalidSettleTimeout):
        api1.channel_open(
            registry_address=app1.default_registry.address,
            token_address=token_address,
            partner_address=address_for_lowest_settle_timeout,
            settle_timeout=BlockTimeout(lowest_valid_settle_timeout - 1),
        )

    # Make sure the smallest settle timeout is accepted
    api1.channel_open(
        registry_address=app1.default_registry.address,
        token_address=token_address,
        partner_address=address_for_lowest_settle_timeout,
        settle_timeout=BlockTimeout(lowest_valid_settle_timeout),
    )

    address_for_highest_settle_timeout = make_address()
    highest_valid_settle_timeout = settle_timeout_max

    # Make sure a large settle timeout is not accepted when opening a channel
    with pytest.raises(InvalidSettleTimeout):
        api1.channel_open(
            registry_address=app1.default_registry.address,
            token_address=token_address,
            partner_address=address_for_highest_settle_timeout,
            settle_timeout=highest_valid_settle_timeout + 1,
        )

    # Make sure the highest settle timeout is accepted
    api1.channel_open(
        registry_address=app1.default_registry.address,
        token_address=token_address,
        partner_address=address_for_highest_settle_timeout,
        settle_timeout=highest_valid_settle_timeout,
    )

    # open is a synchronous api
    api1.channel_open(app1.default_registry.address, token_address, api2.address)
    channels = api1.get_channel_list(registry_address, token_address, api2.address)
    assert len(channels) == 1

    channel12 = get_channelstate(app1, app2, token_network_address)
    assert channel.get_status(channel12) == ChannelState.STATE_OPENED

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

    channel12 = get_channelstate(app1, app2, token_network_address)

    assert channel.get_status(channel12) == ChannelState.STATE_OPENED
    assert channel.get_balance(channel12.our_state, channel12.partner_state) == deposit
    assert channel12.our_state.contract_balance == deposit
    assert api1.get_channel_list(registry_address, token_address, api2.address) == [channel12]

    # there is a channel open. Since healthchecks don't exist anymore,
    # the API still shouldn't know about the NetworkState
    assert api1.get_node_network_state(api2.address) == NetworkState.UNKNOWN
    assert api2.get_node_network_state(api1.address) == NetworkState.UNKNOWN

    api1.channel_close(registry_address, token_address, api2.address)

    # Load the new state with the channel closed
    channel12 = get_channelstate(app1, app2, token_network_address)
    assert channel.get_status(channel12) == ChannelState.STATE_CLOSED

    with pytest.raises(UnexpectedChannelState):
        api1.set_total_channel_deposit(
            registry_address, token_address, api2.address, deposit + 100
        )

    assert wait_for_state_change(
        app1,
        ContractReceiveChannelSettled,
        {
            "canonical_identifier": {
                "token_network_address": token_network_address,
                "channel_identifier": channel12.identifier,
            }
        },
        retry_timeout,
    )


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
def test_same_addresses_for_payment(raiden_network: List[RaidenService], token_addresses):
    app0, _ = raiden_network
    api0 = RaidenAPI(app0)
    registry_address = app0.default_registry.address
    token_address = token_addresses[0]

    with pytest.raises(SamePeerAddress):
        api0.transfer_and_wait(
            registry_address=registry_address,
            token_address=token_address,
            target=TargetAddress(app0.address),
            amount=PaymentAmount(1),
        )
