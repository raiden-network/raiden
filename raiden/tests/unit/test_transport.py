from raiden.network.throttle import TokenBucket


def test_token_bucket():
    capacity = 2
    fill_rate = 2
    token_refill = 1. / fill_rate

    # return constant time to have a predictable refill result
    time = lambda: 1

    bucket = TokenBucket(
        capacity,
        fill_rate,
        time,
    )

    assert bucket.consume(1) == 0
    assert bucket.consume(1) == 0

    for num in range(1, 9):
        assert num * token_refill == bucket.consume(1)
