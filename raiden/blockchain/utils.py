import math

from eth_typing import BlockNumber
from structlog import get_logger

from raiden.blockchain.exceptions import BlockBatchSizeTooSmall
from raiden.settings import BlockBatchSizeConfig

log = get_logger(__name__)


class BlockBatchSizeAdjuster:
    """ Helper to dynamically adjust the block batch size.

    Internally it uses an exponential function of base ``base`` onto which the block range given
    in the config is mapped.

    The default values for ``base`` and ``step_size`` fit well for ranges that span several orders
    of magnitude. For very small ranges those values may need to be adjusted.
    """

    def __init__(
        self,
        block_batch_size_config: BlockBatchSizeConfig,
        base: float = 2.0,
        step_size: float = 1.0,
    ) -> None:
        self._block_batch_size_config = block_batch_size_config
        self._base = base
        self._step_size = step_size

        self._scale_max = math.log(self._block_batch_size_config.max, self._base) + 1
        self._scale_min = math.log(self._block_batch_size_config.min, self._base)
        self._scale_current = math.log(self._block_batch_size_config.initial, self._base)

    def _log(self, previous_batch_size: BlockNumber) -> None:
        batch_size = self.batch_size
        log.debug(
            "Adjusting block batch size",
            batch_size=batch_size,
            previous_batch_size=previous_batch_size,
        )
        if batch_size <= self._block_batch_size_config.warn_threshold:
            log.warning(
                "Block batch size approaching minimum",
                batch_size=batch_size,
                previous_batch_size=previous_batch_size,
                warning_threshold=self._block_batch_size_config.warn_threshold,
                minimum_batch_size=self._block_batch_size_config.min,
            )

    def increase(self) -> None:
        """ Increase the block batch size.

        Does nothing if the value is already at the maximum.
        """
        previous_batch_size = self.batch_size
        if previous_batch_size >= self._block_batch_size_config.max:
            return
        self._scale_current += self._step_size
        self._log(previous_batch_size)

    def decrease(self) -> None:
        """ Decrease the batch size.

        If the current value is already at the minimum raise ``BlockBatchSizeTooSmall``.
        """
        previous_batch_size = self.batch_size
        if previous_batch_size <= self._block_batch_size_config.min:
            raise BlockBatchSizeTooSmall(
                f"The block batch size has fallen below the minimum allowed value of "
                f"{self._block_batch_size_config.min}. This indicates that either your Ethereum "
                f"node or the network connection to it is overloaded or it is running on "
                f"insufficiently powerful hardware."
            )
        self._scale_current -= self._step_size
        self._log(previous_batch_size)

    @property
    def batch_size(self) -> BlockNumber:
        """ Return the current batch size.

        Clamps the value to the range given in the config.
        """
        return max(
            self._block_batch_size_config.min,
            min(
                self._block_batch_size_config.max,
                BlockNumber(int(self._base ** self._scale_current)),
            ),
        )
