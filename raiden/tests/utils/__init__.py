import random


def get_random_bytes(count):
    """Get an array filed with random numbers"""
    return bytes(
        [random.randint(0, 0xff) for _ in range(count)],
    )
