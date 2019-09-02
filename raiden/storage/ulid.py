import random
from dataclasses import dataclass
from time import CLOCK_MONOTONIC_RAW, clock_getres, clock_gettime_ns, time_ns

from gevent.lock import Semaphore

from raiden.utils.typing import Any, Generic, Iterable, Iterator, List, Tuple, TypeVar, cast


@dataclass(frozen=True, order=True)
class ULID:
    """An ULID.

    The generated IDs are lexicographically sorted, however the timestamps are
    *not* representative of wall time.

    SPEC: https://github.com/ulid/spec
    """

    identifier: bytes

    def __post_init__(self) -> None:
        assert len(self.identifier) == 16, "id_ must be 16 bytes long"

    def __str__(self) -> str:
        return f"ULID<{self.identifier.hex()}>"

    @property
    def timestamp(self) -> int:
        """Aproximated timestamp of the database entry.

        There is no lower bound for the skew in time.
        """
        timestamp_bytes = self.identifier[:8]
        return int.from_bytes(timestamp_bytes, "big")


ID = TypeVar("ID", bound=ULID)


class ULIDMonotonicFactory(Generic[ID]):
    """Monotonic ULID factory that guarantees new ULIDs will not decrease.

    This factory does not follow the SPEC. The timestamp is not walltime and
    the precision was increased from ms to ns to guarantee total order.

    time.time() can not be used because it is not monotonic.  The clock can be
    reset by the user, a NTPD daemon, adjusted because of TZ changes, adjusted
    because of leap seconds, etc. Therefore a monotonic clock must be used.
    """

    def __init__(self, start: int) -> None:
        resolution = clock_getres(CLOCK_MONOTONIC_RAW)

        msg = (
            "The monotonic clock must have nanosecond resolution. This is "
            "necessary because multiple state changes can be written on the same "
            "millisecond."
        )
        assert resolution <= 0.000_000_001, msg

        current_time = time_ns()

        if start is None or start < current_time:
            start = current_time

        self._previous_timestamp = start
        self._previous_monotonic = clock_gettime_ns(CLOCK_MONOTONIC_RAW)
        self._lock = Semaphore()

    def new(self) -> ID:
        timestamp: int

        with self._lock:
            # Using RAW to circumvent a bug in Pine64/ARM64 and the 3.x family
            # of Linux Kernels which allowed `CLOCK_MONOTONIC` to go backwards
            # (PR: #4156).
            #
            # A monotonic clock with ns precision must not return the same
            # value twice, looking up the time itself should take more then 1ns,
            # https://www.python.org/dev/peps/pep-0564/#annex-clocks-resolution-in-python
            new_monotonic = clock_gettime_ns(CLOCK_MONOTONIC_RAW)

            assert (
                new_monotonic > self._previous_monotonic
            ), "The monotonic clock must not go backwards"

            delta = new_monotonic - self._previous_monotonic
            timestamp = self._previous_timestamp + delta

            self._previous_monotonic = new_monotonic
            self._previous_timestamp = timestamp

        rnd = random.getrandbits(64)
        identifier = ULID(timestamp.to_bytes(8, "big") + rnd.to_bytes(8, "big"))

        return cast(ID, identifier)

    def prepend_and_save_ids(self, ids: List[ID], items: Iterable[Tuple[Any, ...]]) -> Iterator:
        for item in items:
            next_id = self.new()
            ids.append(next_id)
            yield (next_id, *item)
