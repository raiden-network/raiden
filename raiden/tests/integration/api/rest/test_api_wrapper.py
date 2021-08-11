import re

import pytest
from raiden_api_client import RaidenAPIWrapper
from raiden_api_client.exceptions import InvalidInput

from raiden import waiting
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import BlockNumber


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_wrapper(raiden_network, unregistered_custom_token, retry_timeout, pfs_mock):
    app0, app1 = raiden_network
    pfs_mock.add_apps(raiden_network)

    address1 = to_checksum_address(app0.address)
    address2 = to_checksum_address(app1.address)

    token = to_checksum_address(unregistered_custom_token)

    wrapper = RaidenAPIWrapper(ip=app0.api_server.config.host, port=app0.api_server.config.port)

    # Wait until Raiden can start using the token contract.
    # Here, the block at which the contract was deployed should be confirmed by Raiden.
    # Therefore wait, until that block is received.
    waiting.wait_for_block(
        raiden=app1,
        block_number=BlockNumber(
            app1.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
        ),
        retry_timeout=retry_timeout,
    )

    # Test minting
    resp = wrapper.mint_tokens(receiver=address1, token=token, amount=10)
    assert app0.rpc_client.web3.eth.getTransaction(resp.transaction_hash)

    # Test token registration
    resp = wrapper.register_token(token=token)
    # The token network address will be needed for a later test
    token_network_address = resp.token_network_address
    assert app0.rpc_client.web3.eth.get_code(resp.token_network_address)

    # Test channel opening
    resp = wrapper.open_channel(partner=address2, token=token, deposit=2)
    assert resp.state == "opened"

    # Test channel funding
    resp = wrapper.fund_channel(partner=address2, token=token, deposit=4)
    assert resp.total_deposit == "4"

    # Test transfer
    resp = wrapper.transfer(partner=address2, token=token, amount=1)
    assert resp.amount == "1"

    # Test channel query
    resp = wrapper.get_channels()
    assert resp[0].partner_address == address2

    resp = wrapper.get_channels(token=token)
    assert resp[0].partner_address == address2

    resp = wrapper.get_channels(token=token, partner=address2)
    assert resp.partner_address == address2

    with pytest.raises(InvalidInput):
        wrapper.get_channels(partner=address2)

    # Test payment query
    resp = wrapper.get_payments(partner=address2, token=token)
    assert resp[0].event == "EventPaymentSentSuccess"

    resp = wrapper.get_payments()
    assert resp[0].event == "EventPaymentSentSuccess"

    with pytest.raises(InvalidInput):
        wrapper.get_payments(partner=address2)

    with pytest.raises(InvalidInput):
        wrapper.get_payments(token=token)

    # Test token network query
    resp = wrapper.get_token_network(token=token)
    assert resp == token_network_address

    # Test version query
    resp = wrapper.get_raiden_version()
    assert re.match(r"\d\.\d.\d.*", resp.version)

    # Test address query
    resp = wrapper.get_address()
    assert resp.our_address == address1

    # Test connection query
    resp = wrapper.get_connections()
    assert resp[token]["channels"] == "1"
    assert resp[token]["sum_deposits"] == "4"

    # Test node status query
    resp = wrapper.get_node_status()
    assert isinstance(resp.status, str)

    # Test closing channel
    resp = wrapper.close_channel(partner=address2, token=token)
    # Coop-settle was done, the response should be empty.
    assert not resp
