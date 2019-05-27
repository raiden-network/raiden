import random
from dataclasses import dataclass
from time import get_clock_info, monotonic_ns, time_ns

from gevent.lock import Semaphore

from raiden.utils.typing import Any, Iterable, Iterator, List, Tuple


@dataclass(frozen=True, order=True)
class ULID:
    """An ULID.

    The generated IDs are lexicographically sorted, however the timestamps are
    *not* representative of wall time.

    SPEC: https://github.com/ulid/spec
    """

    identifier: bytes

    def __post_init__(self):
        assert len(self.identifier) == 16, "id_ must be 16 bytes long"

    @property
    def timestamp(self):
        """Aproximated timestamp of the database entry.

        There is no lower bound for the skew in time.
        """
        timestamp_bytes = self.identifier[:8]
        return int.from_bytes(timestamp_bytes, "big")


class ULIDMonotonicFactory:
    """Monotonic ULID factory that guarantees new ULIDs will not be decrease.

    This factory does not follow the SPEC. The timestamp is not walltime and
    the precision was increased from ms to ns to guarantee total order.

    time.time() can not be used because it is not monotonic.  The clock can be
    reset by the user, a NTPD daemon, adjusted because of TZ changes, adjusted
    because of leap seconds, etc. Therefore a monotonic clock must be used.
    """

    def __init__(self, start: int) -> None:
        monotonic_info = get_clock_info("monotonic")

        msg = (
            "The monotonic clock must not be adjustable. A monotonic clock is "
            "*necessary* for safe operation, otherwise database entries may get "
            "swapped around and the queries can return the wrong values."
        )
        assert monotonic_info.adjustable is False, msg

        msg = (
            "The monotonic clock must have nanosecond resolution. This is "
            "necessary because multiple state changes can be written on the same "
            "millisecond."
        )
        assert monotonic_info.resolution <= 0.000_000_001, msg

        current_time = time_ns()

        if start is None or start < current_time:
            start = current_time

        self._previous_timestamp = start
        self._previous_monotonic = monotonic_ns()
        self._lock = Semaphore()

    def new(self) -> ULID:
        timestamp: int

        with self._lock:
            new_monotonic = monotonic_ns()

            msg = (
                "A monotonic clock with ns precision must not return the same "
                "value twice, looking up the time itself should take more then 1ns, "
                "https://www.python.org/dev/peps/pep-0564/#annex-clocks-resolution-in-python."
            )
            assert new_monotonic > self._previous_monotonic, msg

            delta = new_monotonic - self._previous_monotonic
            timestamp = self._previous_timestamp + delta

            self._previous_monotonic = new_monotonic
            self._previous_timestamp = timestamp

        rnd = random.getrandbits(64)
        identifier = timestamp.to_bytes(8, "big") + rnd.to_bytes(8, "big")

        return ULID(identifier)

    def prepend_and_save_ids(self, ids: List[ULID], items: Iterable[Tuple[Any, ...]]) -> Iterator:
        for item in items:
            next_id = self.new()
            ids.append(next_id)
            yield (next_id, *item)
