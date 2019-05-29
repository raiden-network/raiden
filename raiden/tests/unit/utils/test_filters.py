import pytest
from eth_utils import to_bytes, to_int

from raiden.tests.utils import factories
from raiden.utils.filters import (
    get_filter_args_for_all_events_from_channel,
    get_filter_args_for_specific_event_from_channel,
)


def test_get_filter_args(contract_manager):
    channel_identifier = factories.UNIT_CHANNEL_ID
    token_network_address = factories.UNIT_TOKEN_NETWORK_ADDRESS

    event_filter_params = get_filter_args_for_all_events_from_channel(
        token_network_address=token_network_address,
        channel_identifier=channel_identifier,
        contract_manager=contract_manager,
    )

    assert event_filter_params["topics"][0] is None
    assert to_int(hexstr=event_filter_params["topics"][1]) == channel_identifier
    assert to_bytes(hexstr=event_filter_params["address"]) == token_network_address
    assert event_filter_params["fromBlock"] == 0
    assert event_filter_params["toBlock"] == "latest"

    with pytest.raises(ValueError):
        # filter argument generation checks if event type is known
        get_filter_args_for_specific_event_from_channel(
            token_network_address=token_network_address,
            channel_identifier=channel_identifier,
            event_name="NonexistingEvent",
            contract_manager=contract_manager,
        )

    event_filter_params = get_filter_args_for_specific_event_from_channel(
        token_network_address=token_network_address,
        channel_identifier=channel_identifier,
        event_name="ChannelOpened",
        contract_manager=contract_manager,
        from_block=100,
        to_block=200,
    )

    assert event_filter_params["topics"][0] is not None
    assert to_int(hexstr=event_filter_params["topics"][1]) == channel_identifier
    assert to_bytes(hexstr=event_filter_params["address"]) == token_network_address
    assert event_filter_params["fromBlock"] == 100
    assert event_filter_params["toBlock"] == 200
