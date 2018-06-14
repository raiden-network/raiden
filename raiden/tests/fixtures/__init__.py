import pytest
import random


@pytest.fixture
def get_random_bytes():
    """Get an array filed with random numbers"""
    def f(count):
        return bytes(
            [random.randint(0, 0xff) for _ in range(count)]
        )
    return f
