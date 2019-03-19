from unittest.mock import MagicMock

import gevent
import pytest

from raiden.constants import MONITORING_BROADCASTING_ROOM
from raiden.network.transport.matrix.client import Room
from raiden.network.transport.matrix.utils import make_room_alias
from raiden.raiden_service import update_monitoring_service_from_balance_proof
from raiden.tests.utils.messages import make_balance_proof
from raiden.transfer import views


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [1])
def test_monitoring_global_messages(
        token_addresses,
        raiden_chain,
        retry_interval,
        retries_before_backoff,
        token_proxy,
        deploy_service,
        skip_if_not_matrix,
):
    app0, app1 = raiden_chain
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )

    """
    Test that RaidenService sends RequestMonitoring messages to global
    MONITORING_BROADCASTING_ROOM room on newly received balance proofs.
    """
    transport = app0.raiden.transport
    transport._client.api.retry_timeout = 0
    transport._send_raw = MagicMock()

    app0.raiden.config['services']['monitoring_enabled'] = True
    app0.raiden.config['transport']['matrix']['global_rooms'].append(MONITORING_BROADCASTING_ROOM)

    app0.stop()
    app0.start()

    ms_room_name = make_room_alias(transport.network_id, MONITORING_BROADCASTING_ROOM)
    ms_room = transport._global_rooms.get(ms_room_name)
    assert isinstance(ms_room, Room)
    ms_room.send_text = MagicMock(spec=ms_room.send_text)

    transport.log = MagicMock()

    channel_state = views.get_channelstate_by_token_network_and_partner(
        views.state_from_app(app0),
        token_network_identifier,
        app1.raiden.address,
    )

    balance_proof = make_balance_proof(
        token_network_addresss=token_network_identifier,
        channel_identifier=channel_state.identifier,
        signer=app0.raiden.signer,
        amount=1,
    )

    update_monitoring_service_from_balance_proof(
        app0.raiden,
        balance_proof,
    )
    gevent.idle()

    assert ms_room.send_text.call_count == 1
    transport.stop()
    transport.get()
