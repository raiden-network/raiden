import os
import random

from raiden import constants
from raiden.utils.typing import PaymentID, Secret


def random_secret() -> Secret:
    """Return a random 32 byte secret"""
    return Secret(os.urandom(constants.SECRET_LENGTH))


def create_default_identifier() -> PaymentID:
    """Generates a random identifier."""
    return PaymentID(random.randint(0, constants.UINT64_MAX))


def to_rdn(rei: int) -> float:
    """Convert REI value to RDN."""
    return rei / 10 ** 18
