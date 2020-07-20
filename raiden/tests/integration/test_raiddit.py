from typing import List, Tuple

import gevent
import pytest
from eth_typing import BlockNumber

from raiden.api.python import RaidenAPI
from raiden.app import App
from raiden.constants import BLOCK_ID_LATEST
from raiden.network.proxies.token import Token
from raiden.tests.integration.test_integration_pfs import wait_all_apps
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.transfer import transfer
from raiden.transfer import channel, views
from raiden.utils.claim import ClaimGenerator
from raiden.utils.typing import (
    Balance,
    BlockTimeout,
    PaymentAmount,
    PaymentID,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
)
from raiden.waiting import wait_for_block


def get_channel_balances(
    app: App, partner_app: App, token_network_address: TokenNetworkAddress
) -> Tuple[Balance, Balance]:
    chain_state = views.state_from_app(app)
    partner_state = views.state_from_app(partner_app)

    channel_state = views.get_channelstate_by_token_network_and_partner(
        chain_state, token_network_address, partner_state.our_address
    )
    assert channel_state

    return (
        channel.get_balance(channel_state.our_state, channel_state.partner_state),
        channel.get_balance(channel_state.partner_state, channel_state.our_state),
    )


@raise_on_failure
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("settle_timeout_min", [100])
@pytest.mark.parametrize("settle_timeout", [101])
@pytest.mark.parametrize("reveal_timeout", [20])
def test_raiddit(
    raiden_network: List[App],
    token_addresses: List[TokenAddress],
    claim_generator: ClaimGenerator,
    ignore_unrelated_claims: bool,
    settle_timeout: BlockTimeout,
    retry_timeout,
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    token_proxy: Token = app0.raiden.proxy_manager.token(
        token_address=token_address, block_identifier=BLOCK_ID_LATEST,
    )

    chain_state = views.state_from_app(app0)
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )
    assert token_network_address

    balance0 = token_proxy.balance_of(app0.raiden.address)
    balance1 = token_proxy.balance_of(app1.raiden.address)
    balance2 = token_proxy.balance_of(app2.raiden.address)

    # Generate initial claims and test that a transfer works
    claims = claim_generator.add_2_claims(
        token_network_address=token_network_address,
        amounts=(TokenAmount(100), TokenAmount(100)),
        address=app0.raiden.address,
        partner=app1.raiden.address,
    )
    claims.extend(
        claim_generator.add_2_claims(
            token_network_address=token_network_address,
            amounts=(TokenAmount(100), TokenAmount(100)),
            address=app1.raiden.address,
            partner=app2.raiden.address,
        )
    )
    app0.raiden.process_claims({}, claims, ignore_unrelated=ignore_unrelated_claims)
    app1.raiden.process_claims({}, claims, ignore_unrelated=ignore_unrelated_claims)
    app2.raiden.process_claims({}, claims, ignore_unrelated=ignore_unrelated_claims)
    wait_all_apps(raiden_network)

    assert get_channel_balances(app0, app1, token_network_address) == (100, 100)
    assert get_channel_balances(app1, app2, token_network_address) == (100, 100)

    transfer(
        initiator_app=app0,
        target_app=app2,
        token_address=token_address,
        amount=PaymentAmount(50),
        identifier=PaymentID(42),
    )

    gevent.sleep(1)
    assert get_channel_balances(app0, app1, token_network_address) == (48, 152)
    assert get_channel_balances(app1, app2, token_network_address) == (48, 152)

    # TODO: add a burn here

    # Close channels and check on-chain balances
    api1 = RaidenAPI(app1.raiden)
    api1.channel_close(
        registry_address=token_network_registry_address,
        token_address=token_address,
        partner_address=app0.raiden.address,
    )
    api1.channel_close(
        registry_address=token_network_registry_address,
        token_address=token_address,
        partner_address=app2.raiden.address,
    )

    assert token_proxy.balance_of(app0.raiden.address) - balance0 == 0
    assert token_proxy.balance_of(app1.raiden.address) - balance1 == 0
    assert token_proxy.balance_of(app2.raiden.address) - balance2 == 0

    settle_block = BlockNumber(app0.raiden.rpc_client.block_number() + settle_timeout + 10)
    wait_for_block(app0.raiden, settle_block, retry_timeout)
    wait_all_apps(raiden_network)

    assert token_proxy.balance_of(app0.raiden.address) - balance0 == 48
    assert token_proxy.balance_of(app1.raiden.address) - balance1 == 100
    assert token_proxy.balance_of(app2.raiden.address) - balance2 == 152

    # Create a second pair of claims and do another transfer
    claims = claim_generator.add_2_claims(
        token_network_address=token_network_address,
        amounts=(TokenAmount(200), TokenAmount(200)),
        address=app0.raiden.address,
        partner=app1.raiden.address,
    )
    claims.extend(
        claim_generator.add_2_claims(
            token_network_address=token_network_address,
            amounts=(TokenAmount(200), TokenAmount(200)),
            address=app1.raiden.address,
            partner=app2.raiden.address,
        )
    )
    app0.raiden.process_claims({}, claims, ignore_unrelated=ignore_unrelated_claims)
    app1.raiden.process_claims({}, claims, ignore_unrelated=ignore_unrelated_claims)
    app2.raiden.process_claims({}, claims, ignore_unrelated=ignore_unrelated_claims)
    wait_all_apps(raiden_network)

    assert get_channel_balances(app0, app1, token_network_address) == (148, 252)
    assert get_channel_balances(app1, app2, token_network_address) == (148, 252)

    transfer(
        initiator_app=app2,
        target_app=app0,
        token_address=token_address,
        amount=PaymentAmount(50),
        identifier=PaymentID(43),
    )
    gevent.sleep(1)
    assert get_channel_balances(app0, app1, token_network_address) == (200, 200)
    assert get_channel_balances(app1, app2, token_network_address) == (200, 200)

    # TODO: settle once more, check on-chain balances
