import pytest

from raiden.exceptions import SamePeerAddress
from raiden.transfer import views


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_channel_with_self(raiden_network, settle_timeout, token_addresses):
    app0, = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]

    current_chanels = views.list_channelstate_for_tokennetwork(
        views.state_from_app(app0),
        registry_address,
        token_address,
    )
    assert not current_chanels

    token_network_address = app0.raiden.default_registry.get_token_network(token_address)
    token_network0 = app0.raiden.chain.token_network(token_network_address)

    with pytest.raises(SamePeerAddress) as excinfo:
        token_network0.new_netting_channel(
            partner=app0.raiden.address,
            settle_timeout=settle_timeout,
            given_block_identifier='latest',
        )

    assert 'The other peer must not have the same address as the client.' in str(excinfo.value)
