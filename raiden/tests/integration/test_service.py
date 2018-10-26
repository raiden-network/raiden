import pytest

from raiden.messages import Ping
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.geth import wait_until_block
from raiden.transfer import state, views
from raiden.transfer.state_change import Block


@pytest.mark.parametrize('number_of_nodes', [2])
def test_udp_ping_pong(raiden_network, skip_if_not_udp):
    app0, app1 = raiden_network

    ping_message = Ping(nonce=0, current_protocol_version=0)
    app0.raiden.sign(ping_message)
    ping_encoded = ping_message.encode()

    messageid = ('ping', ping_message.nonce, app1.raiden.address)
    async_result = app0.raiden.transport.maybe_sendraw_with_result(
        app1.raiden.address,
        ping_encoded,
        messageid,
    )
    assert async_result.wait(2), 'The message was not processed'

    network_state = views.get_node_network_status(
        views.state_from_app(app0),
        app1.raiden.address,
    )
    assert network_state is state.NODE_NETWORK_REACHABLE


@pytest.mark.parametrize('number_of_nodes', [2])
def test_udp_ping_pong_unreachable_node(raiden_network, skip_if_not_udp):
    app0, app1 = raiden_network

    app1.raiden.transport.stop()

    ping_message = Ping(nonce=0, current_protocol_version=0)
    app0.raiden.sign(ping_message)
    ping_encoded = ping_message.encode()

    messageid = ('ping', ping_message.nonce, app1.raiden.address)
    async_result = app0.raiden.transport.maybe_sendraw_with_result(
        app1.raiden.address,
        ping_encoded,
        messageid,
    )

    nat_keepalive_fail = (
        app0.config['transport']['udp']['nat_keepalive_timeout'] *
        app0.config['transport']['udp']['nat_keepalive_retries'] *
        2  # wait a bit longer to avoid races
    )
    msg = "The message was dropped, it can't be acknowledged"
    assert async_result.wait(nat_keepalive_fail) is None, msg

    network_state = views.get_node_network_status(
        views.state_from_app(app0),
        app1.raiden.address,
    )
    assert network_state is state.NODE_NETWORK_UNREACHABLE


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_tokens', [1])
def test_raiden_service_callback_new_block(raiden_network):
    """ Regression test for: https://github.com/raiden-network/raiden/issues/2894 """
    app0 = raiden_network[0]

    app0.raiden.alarm.stop()
    target_block_num = app0.raiden.chain.block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
    wait_until_block(
        app0.raiden.chain,
        target_block_num,
    )

    latest_block = app0.raiden.chain.get_block(block_identifier='latest')
    app0.raiden._callback_new_block(latest_block=latest_block)
    target_block_num = latest_block['number']

    app0_state_changes = app0.raiden.wal.storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )

    assert must_contain_entry(app0_state_changes, Block, {
        'block_number': target_block_num - DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
    })
    assert not must_contain_entry(app0_state_changes, Block, {
        'block_number': target_block_num,
    })
