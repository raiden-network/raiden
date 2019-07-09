from random import shuffle
from unittest.mock import Mock, patch

import gevent

from raiden.tests.utils.factories import make_chain_state
from raiden.transfer.state import ChannelState, TransactionExecutionStatus
from raiden.waiting import wait_for_channel_in_states


def test_wait_for_channel_in_states():
    """
    wait_for_channel_in_states should wait until all watched channels are
    deleted or in one of the target states.
    """
    container = make_chain_state(number_of_channels=4)
    raiden_mock = Mock(alarm=True)
    raiden_mock.wal.state_manager.current_state = container.chain_state

    channel_ids = [
        channel.canonical_identifier.channel_identifier for channel in container.channels
    ]
    shuffle(channel_ids)

    def sleeper_task():
        wait_for_channel_in_states(
            raiden=raiden_mock,
            payment_network_address=container.payment_network_address,
            token_address=container.token_address,
            channel_ids=channel_ids,
            retry_timeout=0.01,
            target_states=[ChannelState.CHANNEL_STATE_CLOSED],
        )

    with patch("raiden.transfer.views.state_from_raiden", return_value=container.chain_state):
        sleeper = gevent.spawn(sleeper_task)
        for channel_id in channel_ids:
            assert sleeper
            if channel_id % 2 or True:
                del container.token_network.channelidentifiers_to_channels[channel_id]
            else:
                channel = container.token_network.channelidentifiers_to_channels[channel_id]
                close = TransactionExecutionStatus(result=TransactionExecutionStatus.SUCCESS)
                channel.close_transaction = close
            gevent.sleep(0.03)
        assert not sleeper
