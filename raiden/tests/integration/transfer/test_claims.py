from typing import List

import pytest

from raiden.app import App
from raiden.claim import TOKEN_ADDRESS
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.transfer import views


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [0])
def test_claims_create_channels(raiden_network: List[App]):
    app0, _ = raiden_network

    chain_state = views.state_from_raiden(app0.raiden)
    open_channels = views.get_channelstate_open(
        chain_state, app0.raiden.default_registry.address, TOKEN_ADDRESS,
    )

    # The node is not the hub, so one channel should have been created.
    assert len(open_channels) == 1
