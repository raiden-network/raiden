from typing import Iterator


def timeout_exponential_backoff(retries: int, timeout: float, maximum: float) -> Iterator[float]:
    """Timeouts generator with an exponential backoff strategy.
    Timeouts start spaced by `timeout`, after `retries` exponentially increase
    the retry delays until `maximum`, then maximum is returned indefinitely.
    """
    yield timeout

    tries = 1
    while tries < retries:
        tries += 1
        yield timeout

    while timeout < maximum:
        timeout = min(timeout * 2, maximum)
        yield timeout

    while True:
        yield maximum
