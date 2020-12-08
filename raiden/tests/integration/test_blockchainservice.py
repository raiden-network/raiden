import pytest

from raiden.constants import BLOCK_ID_LATEST
from raiden.exceptions import SamePeerAddress
from raiden.raiden_service import RaidenService
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.transfer import views
from raiden.utils.typing import List


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_channel_with_self(raiden_network: List[RaidenService], settle_timeout, token_addresses):
    (app0,) = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    registry_address = app0.default_registry.address
    token_address = token_addresses[0]

    current_chanels = views.list_channelstate_for_tokennetwork(
        views.state_from_raiden(app0), registry_address, token_address
    )
    assert not current_chanels

    token_network_address = app0.default_registry.get_token_network(token_address, BLOCK_ID_LATEST)
    assert token_network_address, "the token must be registered by the fixtures"

    token_network0 = app0.proxy_manager.token_network(token_network_address, BLOCK_ID_LATEST)

    with pytest.raises(SamePeerAddress):
        token_network0.new_netting_channel(
            partner=app0.address,
            settle_timeout=settle_timeout,
            given_block_identifier=BLOCK_ID_LATEST,
        )
