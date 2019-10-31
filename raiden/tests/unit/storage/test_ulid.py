import heapq

from raiden.constants import UINT64_MAX
from raiden.storage.ulid import ULID, ULIDMonotonicFactory


def test_ulid_factory():
    factory = ULIDMonotonicFactory(start=None)  # type: ignore

    entries = [factory.new()]

    # Do a few iteration to test monotonic clock, every new entry must be
    # larger than the previous
    for _ in range(100):
        new_ulid = factory.new()
        prevous_largest = heapq.nlargest(1, entries)[0]
        assert new_ulid > prevous_largest, "monotonicity property is broken"
        heapq.heappush(entries, new_ulid)


def test_ulid_timestamp():
    timestamp_values = [0, 1558988971814002421, UINT64_MAX]
    rnd = 42

    for timestamp in timestamp_values:
        identifier = timestamp.to_bytes(8, "big") + rnd.to_bytes(8, "big")
        assert ULID(identifier).timestamp == timestamp
