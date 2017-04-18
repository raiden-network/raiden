# -*- coding: utf-8 -*-
import pytest

from raiden.tests.utils.transfer import channel


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_get_channel_list(raiden_network, tokens_addresses):
    app0, app1, app2 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = channel(app0, app1, tokens_addresses[0])
    channel1 = channel(app1, app0, tokens_addresses[0])
    channel2 = channel(app0, app2, tokens_addresses[0])

    assert channel0, channel2 in app0.raiden.api.get_channel_list()
    assert channel0 in app0.raiden.api.get_channel_list(partner_address=app1.raiden.address)
    assert channel1 in app1.raiden.api.get_channel_list(token_address=tokens_addresses[0])
    assert channel1 in app1.raiden.api.get_channel_list(tokens_addresses[0], app0.raiden.address)
    assert not app1.raiden.api.get_channel_list(partner_address=app2.raiden.address)

    pytest.raises(
        KeyError,
        app1.raiden.api.get_channel_list,
        token_address=tokens_addresses[0],
        partner_address=app2.raiden.address
    )
    pytest.raises(
        KeyError,
        app2.raiden.api.get_channel_list,
        token_address=app2.raiden.address
    )
