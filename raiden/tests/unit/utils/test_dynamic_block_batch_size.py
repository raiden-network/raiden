import pytest
from eth_typing import BlockNumber

from raiden.blockchain.exceptions import BlockBatchSizeTooSmall
from raiden.blockchain.utils import BlockBatchSizeAdjuster
from raiden.settings import BlockBatchSizeConfig


def test_dynamic_block_batch_size_adjuster():
    config = BlockBatchSizeConfig(
        min=BlockNumber(5),
        warn_threshold=BlockNumber(50),
        initial=BlockNumber(1000),
        max=BlockNumber(100_000),
    )
    adjuster = BlockBatchSizeAdjuster(config, base=2, step_size=1)

    # Check initial value
    assert adjuster.batch_size == 1000

    adjuster.increase()
    assert adjuster.batch_size == 2000

    # Increase all the way to the max value
    for _ in range(6):
        adjuster.increase()
    assert adjuster.batch_size == config.max

    # Ensure we're clamped to the max value
    adjuster.increase()
    assert adjuster.batch_size == config.max

    # Decrease back down to the minimum
    for _ in range(15):
        adjuster.decrease()
    assert adjuster.batch_size == config.min

    # Decreasing below the minimum must raise an exception
    with pytest.raises(BlockBatchSizeTooSmall):
        adjuster.decrease()
