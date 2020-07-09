from pathlib import Path

import pytest
from eth_utils import to_canonical_address
from tools.raiddit.generate_claims import create_hub

from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.transfer import views
from raiden.transfer.state import TokenNetworkGraphState, TokenNetworkState
from raiden.transfer.state_change import (
    ContractReceiveNewTokenNetwork,
    ContractReceiveNewTokenNetworkRegistry,
)
from raiden.utils.typing import TokenAddress, TokenNetworkAddress, TokenNetworkRegistryAddress


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
def test_claims_create_channels(raiden_network, chain_id):

    app0, app1 = raiden_network

    address = app0.raiden.address

    create_hub(
        address,
        TokenNetworkAddress(to_canonical_address("0x679131F591B4f369acB8cd8c51E68596806c3916")),
        chain_id,
        app1.raiden.address,
        1,
        Path("./claims.json"),
    )

    chain_state = views.state_from_raiden(app0.raiden)
    open_channels = views.get_channelstate_open(
        chain_state,
        TokenNetworkRegistryAddress(
            to_canonical_address("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")
        ),
        TokenAddress(to_canonical_address("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")),
    )

    print(f"Open Channels: {open_channels}")
