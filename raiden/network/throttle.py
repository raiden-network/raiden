"""
This module contains the classes responsible to implement the network
communication.
"""
from time import time


class DummyPolicy:
    """Dummy implementation for the throttling policy that always
    returns a wait_time of 0.
    """

    def __init__(self):
        pass

    def consume(self, tokens):  # pylint: disable=unused-argument,no-self-use
        return 0.


class TokenBucket:
    """Implementation of the token bucket throttling algorithm.
    """

    def __init__(self, capacity=10., fill_rate=10., time_function=None):
        self.capacity = float(capacity)
        self.fill_rate = fill_rate
        self.tokens = float(capacity)

        self._time = time_function or time
        self.timestamp = self._time()

    def consume(self, tokens):
        """Consume tokens.
        Args:
            tokens (float): number of transport tokens to consume
        Returns:
            wait_time (float): waiting time for the consumer
        """
        wait_time = 0.
        self.tokens -= tokens
        if self.tokens < 0:
            self._get_tokens()
        if self.tokens < 0:
            wait_time = -self.tokens / self.fill_rate
        return wait_time

    def _get_tokens(self):
        now = self._time()
        self.tokens += self.fill_rate * (now - self.timestamp)
        if self.tokens > self.capacity:
            self.tokens = self.capacity
        self.timestamp = now
