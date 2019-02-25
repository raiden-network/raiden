import gevent
import pytest

from raiden.messages import Ping
from raiden.transfer import state, views


@pytest.mark.parametrize('number_of_nodes', [2])
def test_udp_reachable_node(raiden_network, skip_if_not_udp):
    """A node that answers the ping message must have its state set to
    reachable.
    """
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
def test_udp_unreachable_node(raiden_network, skip_if_not_udp):
    """A node that does *not* answer the ping message must have its state set to
    reachable.
    """
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
def test_suite_survives_unhandled_exception(raiden_network, skip_if_parity):
    """ Commit 56a617085e59fc88517e7043b629ffc9dcc0b8c4 removed code that changed
    gevent's SYSTEM_ERROR for tests. This test aims to show that there is no regression. """
    class UnhandledTestException(Exception):
        pass

    def do_fail(*args, **kwargs):
        raise UnhandledTestException()

    raiden_service = raiden_network[0].raiden
    gevent.spawn(do_fail).join()

    with pytest.raises(UnhandledTestException):
        gevent.spawn(do_fail).get()
    with pytest.raises(UnhandledTestException):
        gevent.getcurrent().throw(UnhandledTestException())
    assert hasattr(raiden_service, 'exception')
    assert raiden_service.exception is None
    raiden_service.alarm.register_callback(do_fail)
    raiden_service.join(timeout=5)
    assert raiden_service.exception is not None
    assert isinstance(raiden_service.exception, UnhandledTestException)
