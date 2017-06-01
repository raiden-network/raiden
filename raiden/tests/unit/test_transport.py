# -*- coding: utf-8 -*-
from raiden.network.transport import TokenBucket


def test_token_bucket():
    capacity = 2
    fill_rate = 2

    # return constant time to have a predictable refill result
    time = lambda: 1

    bucket = TokenBucket(
        capacity,
        fill_rate,
        time,
    )
    assert bucket.consume(1) == 0
    assert bucket.consume(1) == 0
