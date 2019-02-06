import pytest

from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.utils.events import search_for_item
from raiden.transfer.state_change import Block


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_tokens', [1])
def test_regression_filters_must_be_installed_from_confirmed_block(raiden_network):
    """On restarts Raiden must install the filters from the last run's
    confirmed block instead of the latest known block.

    Regression test for: https://github.com/raiden-network/raiden/issues/2894.
    """
    app0 = raiden_network[0]

    app0.raiden.alarm.stop()
    target_block_num = app0.raiden.chain.block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
    app0.raiden.chain.wait_until_block(target_block_num)

    latest_block = app0.raiden.chain.get_block(block_identifier='latest')
    app0.raiden._callback_new_block(latest_block=latest_block)
    target_block_num = latest_block['number']

    app0_state_changes = app0.raiden.wal.storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )

    assert search_for_item(app0_state_changes, Block, {
        'block_number': target_block_num - DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
    })
    assert not search_for_item(app0_state_changes, Block, {
        'block_number': target_block_num,
    })
